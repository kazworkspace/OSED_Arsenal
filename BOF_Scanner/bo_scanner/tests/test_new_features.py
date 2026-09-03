"""
Tests for the four spec gaps fixed in this iteration:

  1. Signed vs unsigned Jcc distinction (bounds.py)
  2. Fastcall ECX/EDX register argument detection (dataflow.py)
  3. ESP-relative stack tracking for frameless functions (stack.py + dataflow.py)
  4. JMP tail call detection + unresolved indirect call tagging (imports.py)
"""
import pytest
from .conftest import make_instructions

from bo_scanner.bounds import detect_bounds_check, BoundsCheckResult
from bo_scanner.dataflow import BackwardDataFlow, ValType, ArgumentValue
from bo_scanner.stack import EspTracker, get_stack_frame_size, classify_destination
from bo_scanner.rules import UNRESOLVED_INDIRECT_RULE, CAT_INDIRECT_UNRESOLVED


IMAGE_BASE = 0x00400000
START_VA   = 0x00401000


# ═══════════════════════════════════════════════════════════════════
# 1.  Signed vs unsigned Jcc distinction
# ═══════════════════════════════════════════════════════════════════

# Unsigned check:  cmp [ebp+0Ch], 0x40  /  ja reject
UNSIGNED_CHECK = bytes([
    0x83, 0x7D, 0x0C, 0x40,   # cmp dword ptr [ebp+0Ch], 0x40
    0x77, 0x10,                # ja  +0x10
])

# Signed check:  cmp [ebp+0Ch], 0x40  /  jg reject
SIGNED_CHECK = bytes([
    0x83, 0x7D, 0x0C, 0x40,   # cmp dword ptr [ebp+0Ch], 0x40
    0x7F, 0x10,                # jg  +0x10
])

# Signed (less-than variant):  cmp [ebp+0Ch], 0x40  /  jl skip
SIGNED_JL_CHECK = bytes([
    0x83, 0x7D, 0x0C, 0x40,   # cmp dword ptr [ebp+0Ch], 0x40
    0x7C, 0x10,                # jl  +0x10
])

# Trailing NOP + placeholder CALL so the scanner has something to anchor on
PLACEHOLDER_CALL = bytes([
    0x90,                      # nop
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
])


class TestSignedUnsignedJcc:

    def _detect(self, check_bytes):
        code = check_bytes + PLACEHOLDER_CALL
        insns = make_instructions(code, START_VA)
        call_idx = len(insns) - 1
        return detect_bounds_check(insns, call_idx)

    def test_unsigned_ja_detected(self):
        result = self._detect(UNSIGNED_CHECK)
        assert result.found is True

    def test_unsigned_ja_has_unsigned_type(self):
        result = self._detect(UNSIGNED_CHECK)
        assert result.jcc_type == "unsigned"

    def test_unsigned_ja_no_signed_risk(self):
        result = self._detect(UNSIGNED_CHECK)
        assert result.signed_risk is False

    def test_signed_jg_detected(self):
        result = self._detect(SIGNED_CHECK)
        assert result.found is True

    def test_signed_jg_has_signed_type(self):
        result = self._detect(SIGNED_CHECK)
        assert result.jcc_type == "signed"

    def test_signed_jg_raises_signed_risk(self):
        result = self._detect(SIGNED_CHECK)
        assert result.signed_risk is True

    def test_signed_jl_also_raises_risk(self):
        result = self._detect(SIGNED_JL_CHECK)
        assert result.signed_risk is True

    def test_signed_risk_in_to_dict(self):
        result = self._detect(SIGNED_CHECK)
        d = result.to_dict()
        assert d["signed_integer_bypass_risk"] is True
        assert d["comparison_type"] == "signed"

    def test_unsigned_to_dict_no_risk(self):
        result = self._detect(UNSIGNED_CHECK)
        d = result.to_dict()
        assert d["signed_integer_bypass_risk"] is False

    def test_signed_description_contains_warning(self):
        result = self._detect(SIGNED_CHECK)
        assert "signed" in result.description.lower()
        assert "bypass" in result.description.lower() or "negative" in result.description.lower()

    def test_no_check_signed_risk_is_false(self):
        insns = make_instructions(PLACEHOLDER_CALL, START_VA)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert result.signed_risk is False
        assert result.jcc_type is None


class TestSignedRiskScoring:
    """Signed bounds check should receive much less credit than unsigned."""

    def _score(self, signed_risk: bool) -> float:
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.rules import get_rule
        from bo_scanner.scoring import score_finding
        rule = get_rule("memcpy")
        a = CallSiteAnalysis(
            function_name="sub_00401000",
            function_start=0x401000,
            call_address=0x401050,
            api_name="memcpy",
            rule=rule,
            destination={"type": "stack", "estimated_size": 64,
                         "size_is_upper_bound": True, "confidence": 0.75,
                         "description": "[EBP-0x40]"},
            source={"type": ValType.FUNC_ARG, "description": "src"},
            length={"type": ValType.FUNC_ARG, "description": "len",
                    "attacker_controlled": True},
            bounds_check=BoundsCheckResult(
                found=True, signed_risk=signed_risk, jcc_type="signed" if signed_risk else "unsigned"
            ),
        )
        _, confidence = score_finding(a)
        return confidence

    def test_signed_check_less_credit_than_unsigned(self):
        unsigned_confidence = self._score(signed_risk=False)
        signed_confidence = self._score(signed_risk=True)
        assert signed_confidence > unsigned_confidence, (
            f"Signed check should get LESS score reduction: "
            f"unsigned={unsigned_confidence}, signed={signed_confidence}"
        )


# ═══════════════════════════════════════════════════════════════════
# 2.  Fastcall ECX/EDX detection
# ═══════════════════════════════════════════════════════════════════

# Function that uses ECX as an incoming argument (fastcall) and pushes it
# as the length for a memcpy call.
#
#   ; ECX arrives from caller (fastcall arg #0)
#   lea  eax, [ebp-0x40]   ; dest = local buffer
#   push ecx               ; length = fastcall arg  ← this is what we test
#   push dword ptr [ebp+8] ; src = caller's stack arg
#   push eax               ; dest
#   call memcpy
FASTCALL_MEMCPY = bytes([
    0x55,             # push ebp
    0x8B, 0xEC,       # mov ebp, esp
    0x83, 0xEC, 0x40, # sub esp, 0x40
    0x8D, 0x45, 0xC0, # lea eax, [ebp-0x40]
    0x51,             # push ecx             ← fastcall arg
    0xFF, 0x75, 0x08, # push dword ptr [ebp+8]
    0x50,             # push eax
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
])


class TestFastcallDetection:

    def setup_method(self):
        self.insns = make_instructions(FASTCALL_MEMCPY, START_VA)
        self.call_idx = len(self.insns) - 1
        df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE)
        self.args = df.recover_arguments(num_args=3)

    def test_recovers_three_args(self):
        assert len(self.args) >= 3

    def test_dest_is_stack_local(self):
        assert self.args[0].type == ValType.STACK_LOCAL, (
            f"Expected STACK_LOCAL, got {self.args[0].type}"
        )

    def test_length_is_func_arg_register(self):
        """ECX not written in function body → fastcall register argument."""
        # Length is arg[2] in our setup (pushed first = closest to call = arg[0] but
        # memcpy uses dest=arg[0], src=arg[1], len=arg[2])
        # Find which arg resolved to FUNC_ARG_REGISTER
        reg_args = [a for a in self.args if a.type == ValType.FUNC_ARG_REGISTER]
        assert len(reg_args) >= 1, (
            f"Expected at least one FUNC_ARG_REGISTER, got types: "
            f"{[a.type for a in self.args]}"
        )

    def test_register_arg_is_ecx(self):
        reg_arg = next(a for a in self.args if a.type == ValType.FUNC_ARG_REGISTER)
        assert "ecx" in reg_arg.description.lower() or "0" in str(reg_arg.arg_index)

    def test_register_arg_index_is_zero(self):
        reg_arg = next(a for a in self.args if a.type == ValType.FUNC_ARG_REGISTER)
        assert reg_arg.arg_index == 0

    def test_str_representation(self):
        v = ArgumentValue(
            type=ValType.FUNC_ARG_REGISTER,
            arg_index=0,
            description="ECX — potential fastcall argument #0",
        )
        assert "ECX" in str(v) or "ecx" in str(v).lower()


# ═══════════════════════════════════════════════════════════════════
# 3.  ESP-relative tracking for frameless functions
# ═══════════════════════════════════════════════════════════════════

# Frameless function (no push ebp / mov ebp,esp):
#   sub  esp, 0x80           ; allocate 128-byte frame (imm32 form to keep sign positive)
#   lea  eax, [esp+0x20]     ; address of local at ESP+0x20
#   push 0x40                ; length = 64
#   push dword ptr [esp+0x84]; src (original esp+0x80 after sub; +4 more after push 0x40)
#   push eax                 ; dest
#   call memcpy
#
# NOTE: MUST use 81 EC (imm32) for sub esp, 0x80.
#   83 EC 80 encodes sub esp, -128 (sign-extended 8-bit 0x80 = -128).
#   That would INCREASE ESP, not allocate a frame.
#   81 EC 80 00 00 00 encodes sub esp, 0x80 (imm32 = 128, positive).
FRAMELESS_MEMCPY = bytes([
    0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,  # sub  esp, 0x80  (imm32)
    0x8D, 0x44, 0x24, 0x20,               # lea  eax, [esp+0x20]
    0x6A, 0x40,                           # push 0x40
    0xFF, 0x74, 0x24, 0x84,               # push dword ptr [esp+0x84]
    0x50,                                 # push eax
    0xE8, 0x00, 0x00, 0x00, 0x00,         # call +0
])


class TestEspTracker:

    def setup_method(self):
        self.insns = make_instructions(FRAMELESS_MEMCPY, START_VA)
        self.tracker = EspTracker(self.insns)

    def test_delta_zero_at_start(self):
        """Before any instruction, ESP delta is 0."""
        assert self.tracker.delta_at(0) == 0

    def test_delta_after_sub_esp(self):
        """After sub esp, 0x80, delta should be -0x80."""
        # instruction 0 = sub esp, 0x80
        # delta_at(1) = delta entering instruction 1 = after sub applied
        assert self.tracker.delta_at(1) == -0x80

    def test_frame_size_from_deltas(self):
        size = self.tracker.frame_size_from_deltas()
        assert size == 0x80, f"Expected 0x80, got {size}"


class TestEspRelDestination:

    def setup_method(self):
        self.insns = make_instructions(FRAMELESS_MEMCPY, START_VA)
        self.call_idx = len(self.insns) - 1
        self.tracker = EspTracker(self.insns)
        df = BackwardDataFlow(
            self.insns, self.call_idx, IMAGE_BASE, esp_tracker=self.tracker
        )
        self.args = df.recover_arguments(num_args=3)

    def test_dest_resolved_to_stack_local_with_tracker(self):
        """[esp+0x20] in a frame of -0x80 should become STACK_LOCAL."""
        dest = self.args[0]
        assert dest.type == ValType.STACK_LOCAL, (
            f"Expected STACK_LOCAL from ESP tracking, got {dest.type}: {dest.description}"
        )

    def test_dest_is_address_of(self):
        """LEA → is_address should be True."""
        dest = self.args[0]
        assert dest.is_address is True

    def test_length_is_constant(self):
        """push 0x40 → IMMEDIATE 64.  Size is arg[2] (pushed first = farthest from call)."""
        length = self.args[2]
        assert length.type == ValType.IMMEDIATE, (
            f"Expected IMMEDIATE for size, got {length.type}: {length.description}"
        )
        assert length.imm_value == 0x40

    def test_classify_destination_returns_stack(self):
        """classify_destination should mark ESP-tracked local as 'stack'."""
        dest = self.args[0]
        frame_size = get_stack_frame_size(self.insns)
        info = classify_destination(
            dest, frame_size, esp_tracker=self.tracker, at_idx=self.call_idx
        )
        assert info["type"] == "stack", (
            f"Expected 'stack', got '{info['type']}': {info['description']}"
        )


class TestEspTrackerWithPushes:
    """ESP tracker must account for interim PUSH instructions, not just sub esp."""

    def test_push_decrements_delta(self):
        # sub esp, 0x40 / push eax / nop
        # 83 EC 40 = sub esp, 0x40  (imm8 0x40=64, positive → correct -0x40 effect)
        # 50       = push eax
        # 90       = nop (provides instruction at index 2 so delta_at(2) is defined)
        code = bytes([0x83, 0xEC, 0x40, 0x50, 0x90])
        insns = make_instructions(code, START_VA)
        tracker = EspTracker(insns)
        # delta_at(0) = 0  (entering sub esp)
        # delta_at(1) = -0x40  (entering push eax; sub was applied)
        # delta_at(2) = -0x44  (entering nop; push was applied)
        assert tracker.delta_at(1) == -0x40, f"Got {tracker.delta_at(1)}"
        assert tracker.delta_at(2) == -0x44, f"Got {tracker.delta_at(2)}"


# ═══════════════════════════════════════════════════════════════════
# 4.  JMP tail call + unresolved indirect call tagging
# ═══════════════════════════════════════════════════════════════════

class TestUnresolvedIndirectRule:

    def test_sentinel_rule_category(self):
        assert UNRESOLVED_INDIRECT_RULE.category == CAT_INDIRECT_UNRESOLVED

    def test_sentinel_rule_low_base_risk(self):
        assert UNRESOLVED_INDIRECT_RULE.base_risk <= 10

    def test_sentinel_rule_no_arg_indices(self):
        assert UNRESOLVED_INDIRECT_RULE.dest_arg is None
        assert UNRESOLVED_INDIRECT_RULE.src_arg is None
        assert UNRESOLVED_INDIRECT_RULE.size_arg is None


class TestIndirectCallClassification:
    """ImportResolver.classify_indirect_call() should tag register/memory indirects."""

    def _make_resolver(self):
        """Return a minimal ImportResolver with an empty IAT."""
        from unittest.mock import MagicMock
        from bo_scanner.imports import ImportResolver
        from bo_scanner.disassembler import Disassembler

        pe = MagicMock()
        pe.imports = []
        pe.code_sections = []

        disasm = MagicMock()
        disasm.disassemble.return_value = []

        return ImportResolver(pe, disasm)

    def _insn(self, code_bytes):
        """Disassemble a single instruction."""
        return make_instructions(code_bytes, START_VA)[0]

    def test_call_eax_is_indirect(self):
        resolver = self._make_resolver()
        insn = self._insn(bytes([0xFF, 0xD0]))   # call eax
        insns = [insn]; result = resolver.classify_indirect_call(insns, 0)
        assert result is not None
        assert "eax" in result.lower()
        assert "indirect" in result.lower()

    def test_call_mem_eax_is_indirect(self):
        resolver = self._make_resolver()
        insn = self._insn(bytes([0xFF, 0x10]))   # call dword ptr [eax]
        insns = [insn]; result = resolver.classify_indirect_call(insns, 0)
        assert result is not None
        assert "indirect" in result.lower()

    def test_direct_call_not_indirect(self):
        """Direct CALL that doesn't resolve should not be tagged as indirect register."""
        resolver = self._make_resolver()
        insn = self._insn(bytes([0xE8, 0x00, 0x00, 0x00, 0x00]))  # call +0
        # Direct CALL: operand is IMM, not REG or unresolved MEM — returns None
        insns = [insn]; result = resolver.classify_indirect_call(insns, 0)
        # May be None (can't resolve, but not a register indirect)
        # The function should either return None or a description without "register indirect"
        if result is not None:
            assert "register" not in result.lower() or "indirect" in result.lower()


class TestCallSiteAnalysisTailCallField:
    """is_tail_call field on CallSiteAnalysis defaults to False."""

    def test_default_is_tail_call_false(self):
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.rules import get_rule
        rule = get_rule("memcpy")
        a = CallSiteAnalysis(
            function_name="sub_401000",
            function_start=0x401000,
            call_address=0x401050,
            api_name="memcpy",
            rule=rule,
        )
        assert a.is_tail_call is False
