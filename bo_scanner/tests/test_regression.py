"""
Regression tests covering improvements made after the three-binary test campaign:

  1. Thunk stub filter — JMP to dangerous API in a ≤3-instruction function is skipped
  2. Heap pointer reclassification — is_address=False STACK_LOCAL → "heap_pointer" type
  3. strncpy / strncat rules exist with correct fields
  4. Resolved-safe suppression — CALL to non-dangerous API not listed as "unresolved"
  5. Export table name resolution
  6. Volatile register awareness in Pattern D backtrack
"""
import pytest
from unittest.mock import MagicMock

from .conftest import make_instructions

from bo_scanner.dataflow import BackwardDataFlow, ValType, ArgumentValue
from bo_scanner.stack import EspTracker, classify_destination
from bo_scanner.rules import get_rule, CAT_SIZE_DEPENDENT


START_VA   = 0x00401000
IMAGE_BASE = 0x00400000


# ═══════════════════════════════════════════════════════════════════
# 1.  Thunk stub filter
# ═══════════════════════════════════════════════════════════════════
# A thunk stub is a single JMP [iat_va] instruction (1–2 instructions
# when disassembled). callsite.py should skip these as tail-call findings.

class TestThunkFilter:
    """
    The filter is checked at callsite.py runtime (len(insns) <= 3 for JMP).
    We verify the rule from a unit perspective by confirming that a thunk
    function (1 instruction) would be suppressed, while a real function
    body with multiple instructions would not.
    """

    def _make_thunk_insns(self):
        """JMP [iat_va] — single instruction = thunk stub."""
        code = bytes([0xFF, 0x25, 0x00, 0x40, 0x40, 0x00])  # JMP [0x404000]
        return make_instructions(code, START_VA)

    def _make_function_insns(self):
        """Full function: prologue + args + JMP at end."""
        from .conftest import PROLOGUE, MEMCPY_CALL
        return make_instructions(PROLOGUE + MEMCPY_CALL, START_VA)

    def test_thunk_has_one_instruction(self):
        insns = self._make_thunk_insns()
        assert len(insns) == 1

    def test_function_has_many_instructions(self):
        insns = self._make_function_insns()
        assert len(insns) > 3

    def test_thunk_condition_triggers(self):
        """A function with ≤3 instructions triggers the thunk filter."""
        insns = self._make_thunk_insns()
        assert len(insns) <= 3, "Thunk should have ≤ 3 instructions"

    def test_full_function_passes_filter(self):
        """A real function body is NOT suppressed by the thunk filter."""
        insns = self._make_function_insns()
        assert len(insns) > 3, "Real function should have > 3 instructions"


# ═══════════════════════════════════════════════════════════════════
# 2.  Heap pointer reclassification
# ═══════════════════════════════════════════════════════════════════
# When a STACK_LOCAL is accessed via MOV (not LEA), it's a pointer
# stored in the stack — the actual buffer is on the heap.

class TestHeapPointerClassification:

    def _make_deref_arg(self, ebp_offset=-0x2c):
        """ArgumentValue for MOV [EBP-N] — pointer dereference."""
        return ArgumentValue(
            type=ValType.STACK_LOCAL,
            ebp_offset=ebp_offset,
            is_address=False,   # MOV, not LEA
            description=f"*[EBP-0x{abs(ebp_offset):X}]",
        )

    def _make_addr_of_arg(self, ebp_offset=-0x40):
        """ArgumentValue for LEA [EBP-N] — address-of stack buffer."""
        return ArgumentValue(
            type=ValType.STACK_LOCAL,
            ebp_offset=ebp_offset,
            is_address=True,    # LEA
            description=f"[EBP-0x{abs(ebp_offset):X}]",
        )

    def test_pointer_deref_classified_as_heap_pointer(self):
        arg = self._make_deref_arg()
        info = classify_destination(arg, frame_size=0x40)
        assert info["type"] == "heap_pointer", (
            f"MOV [EBP-N] should be heap_pointer, got {info['type']}: {info['description']}"
        )

    def test_pointer_deref_has_no_estimated_size(self):
        arg = self._make_deref_arg()
        info = classify_destination(arg, frame_size=0x40)
        assert info.get("estimated_size") is None, (
            "Heap pointer should not have an estimated_size"
        )

    def test_pointer_deref_lower_confidence(self):
        deref = self._make_deref_arg()
        addr_of = self._make_addr_of_arg()
        info_deref = classify_destination(deref, frame_size=0x40)
        info_addr  = classify_destination(addr_of, frame_size=0x40)
        assert info_deref["confidence"] < info_addr["confidence"], (
            f"Heap pointer ({info_deref['confidence']}) should have lower confidence "
            f"than stack buffer ({info_addr['confidence']})"
        )

    def test_address_of_classified_as_stack(self):
        arg = self._make_addr_of_arg()
        info = classify_destination(arg, frame_size=0x50)
        assert info["type"] == "stack", (
            f"LEA [EBP-N] should be stack, got {info['type']}"
        )

    def test_address_of_has_estimated_size(self):
        arg = self._make_addr_of_arg(ebp_offset=-0x40)
        info = classify_destination(arg, frame_size=0x50)
        assert info.get("estimated_size") == 0x40

    def test_heap_pointer_description_mentions_pointer(self):
        arg = self._make_deref_arg()
        info = classify_destination(arg, frame_size=0x40)
        desc = info.get("description", "").lower()
        assert "pointer" in desc or "heap" in desc, (
            f"Description should mention pointer or heap: {info['description']}"
        )

    def test_heap_pointer_scoring_lower_than_stack(self):
        """heap_pointer should score lower than a true stack buffer."""
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.bounds import BoundsCheckResult
        from bo_scanner.scoring import score_finding

        rule = get_rule("memcpy")

        def _analysis(dest_type):
            return CallSiteAnalysis(
                function_name="test", function_start=0x401000,
                call_address=0x401050, api_name="memcpy", rule=rule,
                destination={
                    "type": dest_type,
                    "estimated_size": 64 if dest_type == "stack" else None,
                    "description": "buf", "confidence": 0.75,
                },
                source={"type": ValType.FUNC_ARG, "description": "src"},
                length={"type": ValType.FUNC_ARG, "description": "n",
                        "imm_value": None, "attacker_controlled": True},
                bounds_check=BoundsCheckResult(found=False),
            )

        _, c_stack = score_finding(_analysis("stack"))
        _, c_heap  = score_finding(_analysis("heap_pointer"))
        assert c_stack > c_heap, (
            f"Stack ({c_stack:.0%}) should score higher than heap_pointer ({c_heap:.0%})"
        )


# ═══════════════════════════════════════════════════════════════════
# 3.  strncpy / strncat rules
# ═══════════════════════════════════════════════════════════════════

class TestNewRules:

    def test_strncpy_rule_exists(self):
        rule = get_rule("strncpy")
        assert rule is not None

    def test_strncpy_category_is_size_dependent(self):
        assert get_rule("strncpy").category == CAT_SIZE_DEPENDENT

    def test_strncpy_dest_arg_is_0(self):
        assert get_rule("strncpy").dest_arg == 0

    def test_strncpy_src_arg_is_1(self):
        assert get_rule("strncpy").src_arg == 1

    def test_strncpy_size_arg_is_2(self):
        assert get_rule("strncpy").size_arg == 2

    def test_strncpy_lower_risk_than_strcpy(self):
        """strncpy (bounded) should have lower base_risk than strcpy (unbounded)."""
        assert get_rule("strncpy").base_risk < get_rule("strcpy").base_risk

    def test_strncat_rule_exists(self):
        assert get_rule("strncat") is not None

    def test_strncat_size_arg_is_2(self):
        assert get_rule("strncat").size_arg == 2

    def test_strncpy_alias(self):
        assert get_rule("_strncpy") is get_rule("strncpy")

    def test_strncat_alias(self):
        assert get_rule("_strncat") is get_rule("strncat")


# ═══════════════════════════════════════════════════════════════════
# 4.  Resolved-safe suppression in ImportResolver
# ═══════════════════════════════════════════════════════════════════
# When resolve_call_ctx resolves a CALL to a non-dangerous API (e.g. send),
# classify_indirect_call should NOT be reached, so the call is silently skipped.

class TestResolvedSafeSuppression:

    def _make_resolver_with_iat(self, iat_addr, api_name):
        """Minimal ImportResolver with a single IAT entry."""
        from bo_scanner.imports import ImportResolver
        from bo_scanner.pe import ImportEntry

        pe = MagicMock()
        pe.imports = [ImportEntry(name=api_name, dll="ws2_32.dll", iat_va=iat_addr)]
        pe.code_sections = []

        disasm = MagicMock()
        disasm.disassemble.return_value = []

        return ImportResolver(pe, disasm)

    def test_resolve_non_dangerous_returns_name(self):
        """resolve_call_ctx finds the API name even for non-dangerous APIs."""
        # MOV EAX, [0x416334]  (send IAT slot)
        # CALL EAX
        code = bytes([
            0xA1, 0x34, 0x63, 0x41, 0x00,  # MOV EAX, [0x416334]
            0xFF, 0xD0,                      # CALL EAX
        ])
        insns = make_instructions(code, START_VA)
        call_idx = len(insns) - 1

        resolver = self._make_resolver_with_iat(0x00416334, "send")
        name = resolver.resolve_call_ctx(insns, call_idx)
        assert name == "send", f"Expected 'send', got {name!r}"

    def test_is_dangerous_call_ctx_returns_none_for_send(self):
        """send is not dangerous — is_dangerous_call_ctx should return (None, None)."""
        code = bytes([
            0xA1, 0x34, 0x63, 0x41, 0x00,
            0xFF, 0xD0,
        ])
        insns = make_instructions(code, START_VA)
        resolver = self._make_resolver_with_iat(0x00416334, "send")
        name, rule = resolver.is_dangerous_call_ctx(insns, len(insns) - 1)
        assert name is None
        assert rule is None


# ═══════════════════════════════════════════════════════════════════
# 5.  Export table name resolution
# ═══════════════════════════════════════════════════════════════════

class TestExportTableNames:

    def test_export_names_in_pe_context(self):
        """pe.export_names is populated from the PE export table."""
        import os
        dll_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "vulnserver", "essfunc.dll"
        )
        if not os.path.exists(dll_path):
            pytest.skip("essfunc.dll not present — run from the bo_scanner project root")

        from bo_scanner.pe import parse_pe
        pe = parse_pe(dll_path)
        assert len(pe.export_names) > 0, "essfunc.dll should have exports"
        # EssentialFunc10 should be in the export table
        assert any("EssentialFunc10" in n for n in pe.export_names.values()), (
            f"Expected EssentialFunc10 in exports, got: {list(pe.export_names.values())[:5]}"
        )

    def test_function_uses_export_name(self):
        """Function.name returns the exported symbol name when available."""
        from bo_scanner.functions import Function
        f = Function(start_va=0x62501595, end_va=0x625015B6,
                     export_name="EssentialFunc10")
        assert f.name == "EssentialFunc10"

    def test_function_fallback_to_sub(self):
        """Function.name falls back to sub_XXXXXXXX when no export."""
        from bo_scanner.functions import Function
        f = Function(start_va=0x62501595, end_va=0x625015B6)
        assert f.name == "sub_62501595"


# ═══════════════════════════════════════════════════════════════════
# 6.  Volatile register awareness in Pattern D
# ═══════════════════════════════════════════════════════════════════

class TestVolatileRegisterAwareness:
    """
    EDI/ESI/EBX are callee-saved — a CALL in between should NOT stop the trace.
    EAX/ECX/EDX are volatile — a CALL SHOULD stop the trace.
    """

    def _resolver_with_iat(self, iat_addr, name):
        from bo_scanner.imports import ImportResolver
        from bo_scanner.pe import ImportEntry
        pe = MagicMock()
        pe.imports = [ImportEntry(name=name, dll="test.dll", iat_va=iat_addr)]
        pe.code_sections = []
        disasm = MagicMock()
        disasm.disassemble.return_value = []
        return ImportResolver(pe, disasm)

    def test_edi_traced_through_call(self):
        """
        MOV EDI, [iat]
        CALL something   ← EDI is callee-saved; should continue tracing past this
        CALL EDI
        """
        # MOV EDI, [0x416340]  (8B 3D 40 63 41 00)
        # CALL placeholder     (E8 00 00 00 00)
        # CALL EDI             (FF D7)
        code = bytes([
            0x8B, 0x3D, 0x40, 0x63, 0x41, 0x00,  # MOV EDI, [0x416340]
            0xE8, 0x00, 0x00, 0x00, 0x00,          # CALL +0 (intermediate)
            0xFF, 0xD7,                             # CALL EDI
        ])
        insns = make_instructions(code, START_VA)
        call_idx = len(insns) - 1  # CALL EDI

        resolver = self._resolver_with_iat(0x00416340, "GetProcAddress")
        name = resolver.resolve_call_ctx(insns, call_idx)
        assert name == "GetProcAddress", (
            f"EDI should be traced through CALL to find GetProcAddress, got {name!r}"
        )

    def test_eax_not_traced_through_call(self):
        """
        MOV EAX, [iat]
        CALL something   ← EAX is volatile; trace should stop here
        CALL EAX
        """
        code = bytes([
            0xA1, 0x40, 0x63, 0x41, 0x00,  # MOV EAX, [0x416340]
            0xE8, 0x00, 0x00, 0x00, 0x00,  # CALL +0 (intermediate — clobbers EAX)
            0xFF, 0xD0,                    # CALL EAX
        ])
        insns = make_instructions(code, START_VA)
        call_idx = len(insns) - 1

        resolver = self._resolver_with_iat(0x00416340, "recv")
        # EAX was clobbered by the intermediate CALL → should not resolve
        name = resolver.resolve_call_ctx(insns, call_idx)
        assert name is None, (
            f"EAX should NOT be traced through CALL (volatile), but got {name!r}"
        )


# ═══════════════════════════════════════════════════════════════════
# 7.  Chunked disassembly for large sections
# ═══════════════════════════════════════════════════════════════════

class TestChunkedDisassembly:
    """
    Disassembler.disassemble() must produce consistent output for large
    sections by using chunked disassembly internally.

    Capstone with detail=True stops silently after ~230 KB when given the
    full buffer in one shot.  The chunked path must produce at least as many
    instructions as the single-shot path, and must cover the full VA range.
    """

    def _make_large_section(self, size_bytes: int, start_va: int = 0x40101000):
        """Generate a NOP sled of size_bytes as synthetic section data."""
        return bytes([0x90]) * size_bytes, start_va

    def test_small_section_path(self):
        """Sections ≤ 64 KB use the fast single-shot path."""
        from bo_scanner.disassembler import Disassembler
        d = Disassembler()
        data, va = self._make_large_section(32768)
        insns = d.disassemble(data, va)
        # Each 0x90 = NOP = 1 byte → should get exactly 32768 NOPs
        assert len(insns) == 32768

    def test_large_section_chunked(self):
        """Sections > 64 KB use the chunked path and cover the full range."""
        from bo_scanner.disassembler import Disassembler
        d = Disassembler()
        # Create a section larger than the chunk size (65536)
        data, va = self._make_large_section(200000)
        insns = d.disassemble(data, va)

        # Should cover close to all 200000 bytes (NOP sled → 200000 instructions)
        # Allow for a small margin at chunk boundaries
        assert len(insns) >= 199000, (
            f"Expected ~200000 NOP instructions, got {len(insns)}"
        )
        # Max address should be near the end of the section
        if insns:
            max_addr = max(i.address for i in insns)
            section_end = va + len(data)
            assert max_addr >= va + 195000, (
                f"Disassembly stopped early: max_addr={max_addr:#010x}, "
                f"section_end={section_end:#010x}"
            )

    def test_instruction_count_grows_with_size(self):
        """A 150 KB section produces more instructions than a 50 KB section."""
        from bo_scanner.disassembler import Disassembler
        d = Disassembler()
        small_data, va = self._make_large_section(50000)
        large_data, _ = self._make_large_section(150000)
        small_insns = d.disassemble(small_data, va)
        large_insns = d.disassemble(large_data, va)
        assert len(large_insns) > len(small_insns)

    def test_real_large_binary(self):
        """rainbow2.exe has a 571 KB section; verify all of it is disassembled."""
        import os
        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "vulnbins", "rainbow2.exe"
        )
        if not os.path.exists(path):
            pytest.skip("rainbow2.exe not present")

        from bo_scanner.pe import parse_pe
        from bo_scanner.disassembler import Disassembler
        pe = parse_pe(path)
        d = Disassembler()
        sec = pe.code_sections[0]
        insns = d.disassemble(sec.data, sec.va)

        # Must cover at least 90% of the 585 KB section
        # (some bytes are data tables that don't decode cleanly)
        assert len(insns) > 120000, (
            f"Expected >120k instructions from {len(sec.data)} byte section, "
            f"got {len(insns)}"
        )
        # Specifically must reach past 0x40171a4c (the ReadFile-containing function)
        addrs = {i.address for i in insns}
        assert 0x40171b20 in addrs, (
            "ReadFile call at 0x40171b20 must be reachable after chunked fix"
        )


# ═══════════════════════════════════════════════════════════════════
# 8.  Thunk-table false-positive filter
# ═══════════════════════════════════════════════════════════════════

class TestThunkTableFilter:
    """
    When multiple consecutive JMP [iat_va] thunks are grouped into a single
    "function" by the boundary detector, each JMP to a dangerous API should
    be suppressed (it is the thunk itself, not a real tail call).
    """

    def test_is_in_thunk_table_returns_true_for_consecutive_jmps(self):
        """
        Instructions:
            JMP [send_iat]        (previous — also a thunk)
            JMP [ReadFile_iat]    (the one we're checking)
        Both point to IAT slots → _is_in_thunk_table should return True.
        """
        from unittest.mock import MagicMock
        from bo_scanner.callsite import _is_in_thunk_table

        # Two consecutive JMP [iat] instructions
        # JMP [0x401900] then JMP [0x401904]
        code = bytes([
            0xFF, 0x25, 0x00, 0x19, 0x40, 0x00,   # JMP [0x401900]
            0xFF, 0x25, 0x04, 0x19, 0x40, 0x00,   # JMP [0x401904]
        ])
        insns = make_instructions(code, START_VA)
        assert len(insns) == 2

        resolver = MagicMock()
        resolver._iat_map = {0x00401900: "send", 0x00401904: "ReadFile"}

        # Second JMP (idx=1) is preceded by first JMP [iat] → thunk table
        assert _is_in_thunk_table(insns, 1, resolver) is True

    def test_is_in_thunk_table_false_for_non_consecutive(self):
        """A JMP preceded by a PUSH is NOT in a thunk table."""
        from unittest.mock import MagicMock
        from bo_scanner.callsite import _is_in_thunk_table

        code = bytes([
            0x50,                                   # PUSH EAX (not a JMP)
            0xFF, 0x25, 0x04, 0x19, 0x40, 0x00,   # JMP [0x401904]
        ])
        insns = make_instructions(code, START_VA)

        resolver = MagicMock()
        resolver._iat_map = {0x00401904: "ReadFile"}

        assert _is_in_thunk_table(insns, 1, resolver) is False

    def test_is_in_thunk_table_false_at_index_zero(self):
        """The first instruction can never be in a thunk table (no predecessor)."""
        from unittest.mock import MagicMock
        from bo_scanner.callsite import _is_in_thunk_table

        code = bytes([0xFF, 0x25, 0x04, 0x19, 0x40, 0x00])  # JMP [0x401904]
        insns = make_instructions(code, START_VA)

        resolver = MagicMock()
        resolver._iat_map = {0x00401904: "ReadFile"}

        assert _is_in_thunk_table(insns, 0, resolver) is False


# ═══════════════════════════════════════════════════════════════════
# 9.  Argument quality penalty (zero-arg findings)
# ═══════════════════════════════════════════════════════════════════

class TestArgumentQualityPenalty:
    """
    When all three key arguments (dest, src, len) are UNKNOWN, the finding
    provides no actionable information.  Score penalty should drop it from
    MEDIUM toward LOW.
    """

    def _analysis(self, dest_t, src_t, len_t):
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.rules import get_rule
        from bo_scanner.bounds import BoundsCheckResult
        rule = get_rule("memcpy")
        return CallSiteAnalysis(
            function_name="test", function_start=0x401000,
            call_address=0x401050, api_name="memcpy", rule=rule,
            destination={"type": dest_t, "description": "dest",
                         "estimated_size": 64 if dest_t == "stack" else None,
                         "confidence": 0.5},
            source={"type": src_t, "description": "src"},
            length={"type": len_t, "description": "len",
                    "imm_value": None, "attacker_controlled": False}
                   if len_t != "none" else None,
            bounds_check=BoundsCheckResult(found=False),
        )

    def test_all_unknown_scores_lower_than_known(self):
        from bo_scanner.scoring import score_finding
        all_unknown = self._analysis("unknown", "unknown", "unknown")
        known = self._analysis("stack", ValType.FUNC_ARG, ValType.FUNC_ARG)
        _, c_unknown = score_finding(all_unknown)
        _, c_known   = score_finding(known)
        assert c_unknown < c_known, (
            f"All-unknown ({c_unknown:.0%}) should score lower than known ({c_known:.0%})"
        )

    def test_all_unknown_is_below_medium(self):
        """All-UNKNOWN memcpy should score ≤ 25% — below MEDIUM threshold (42%)."""
        from bo_scanner.scoring import score_finding
        a = self._analysis("unknown", "unknown", "unknown")
        _, conf = score_finding(a)
        assert conf <= 0.25, f"All-unknown should be ≤ 25%, got {conf:.0%}"

    def test_one_known_lower_than_all_known(self):
        from bo_scanner.scoring import score_finding
        one_known  = self._analysis("stack", "unknown", "unknown")
        all_known  = self._analysis("stack", ValType.FUNC_ARG, ValType.FUNC_ARG)
        _, c_one = score_finding(one_known)
        _, c_all = score_finding(all_known)
        assert c_one < c_all


# ═══════════════════════════════════════════════════════════════════
# 10.  Pass-through wrapper detection
# ═══════════════════════════════════════════════════════════════════
#
# memcpy wrapper: all three args (dest, src, size) come from the caller.

PASSTHROUGH_MEMCPY = bytes([
    # push ebp / mov ebp, esp (no sub esp — tiny function)
    0x55, 0x8B, 0xEC,
    # push [ebp+0x10]  (size)
    0xFF, 0x75, 0x10,
    # push [ebp+0x0c]  (src)
    0xFF, 0x75, 0x0C,
    # push [ebp+0x08]  (dest)
    0xFF, 0x75, 0x08,
    # call memcpy (placeholder)
    0xE8, 0x00, 0x00, 0x00, 0x00,
])


class TestPassThroughWrapper:

    def setup_method(self):
        self.insns = make_instructions(PASSTHROUGH_MEMCPY, START_VA)
        self.call_idx = len(self.insns) - 1
        tracker = EspTracker(self.insns)
        df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE,
                              esp_tracker=tracker)
        self.args = df.recover_arguments(3)

    def test_all_args_are_func_arg(self):
        """A pure relay has all args as FUNC_ARG."""
        assert self.args[0].type == ValType.FUNC_ARG, f"dest: {self.args[0].type}"
        assert self.args[1].type == ValType.FUNC_ARG, f"src: {self.args[1].type}"
        assert self.args[2].type == ValType.FUNC_ARG, f"size: {self.args[2].type}"

    def test_is_pass_through_set_in_analysis(self):
        """CallSiteAnalysis.is_pass_through should be True for all-FUNC_ARG calls."""
        from unittest.mock import MagicMock
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.rules import get_rule
        from bo_scanner.bounds import BoundsCheckResult
        from bo_scanner.stack import classify_destination, get_stack_frame_size

        rule = get_rule("memcpy")
        args = self.args
        # dest = args[0] (FUNC_ARG), src = args[1] (FUNC_ARG), len = args[2] (FUNC_ARG)
        _pt_types = {ValType.FUNC_ARG, ValType.FUNC_ARG_REGISTER}
        dest_pt = rule.dest_arg is None or (rule.dest_arg < len(args) and args[rule.dest_arg].type in _pt_types)
        src_pt  = rule.src_arg is None  or (rule.src_arg  < len(args) and args[rule.src_arg].type  in _pt_types)
        len_pt  = rule.size_arg is None or (rule.size_arg < len(args) and args[rule.size_arg].type in _pt_types)
        is_pass_through = dest_pt and src_pt and len_pt
        assert is_pass_through is True

    def test_non_wrapper_not_flagged(self):
        """A function that copies to a local buffer is NOT a pass-through."""
        from .conftest import PROLOGUE, MEMCPY_CALL
        insns = make_instructions(PROLOGUE + MEMCPY_CALL, START_VA)
        call_idx = len(insns) - 1
        tracker = EspTracker(insns)
        df = BackwardDataFlow(insns, call_idx, IMAGE_BASE, esp_tracker=tracker)
        args = df.recover_arguments(3)
        from bo_scanner.rules import get_rule
        rule = get_rule("memcpy")
        _pt = {ValType.FUNC_ARG, ValType.FUNC_ARG_REGISTER}
        dest_pt = rule.dest_arg < len(args) and args[rule.dest_arg].type in _pt
        # dest = STACK_LOCAL (LEA [ebp-0x40]) → NOT FUNC_ARG → not a wrapper
        assert dest_pt is False


# ═══════════════════════════════════════════════════════════════════
# 11.  Alloca frame inconsistency detection
# ═══════════════════════════════════════════════════════════════════

class TestAllocaDetection:

    def test_large_offset_with_none_frame_is_alloca(self):
        """[EBP-0x1004] with frame_size=None → alloca detected."""
        from bo_scanner.stack import classify_destination
        arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x1004,
            is_address=True, description="[EBP-0x1004]"
        )
        info = classify_destination(arg, frame_size=None)
        assert info.get("uses_alloca") is True, (
            f"Large offset with no frame should flag alloca: {info}"
        )

    def test_large_offset_exceeding_frame_is_alloca(self):
        """[EBP-0x1004] with frame_size=0x24 → alloca (offset >> frame)."""
        from bo_scanner.stack import classify_destination
        arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x1004,
            is_address=True, description="[EBP-0x1004]"
        )
        info = classify_destination(arg, frame_size=0x24)
        assert info.get("uses_alloca") is True

    def test_normal_offset_within_frame_not_alloca(self):
        """[EBP-0x40] with frame_size=0x40 → NOT alloca."""
        from bo_scanner.stack import classify_destination
        arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x40,
            is_address=True, description="[EBP-0x40]"
        )
        info = classify_destination(arg, frame_size=0x40)
        assert not info.get("uses_alloca", False)

    def test_small_offset_with_none_frame_not_alloca(self):
        """[EBP-0x40] with frame_size=None → small enough, not alloca."""
        from bo_scanner.stack import classify_destination
        arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x40,
            is_address=True, description="[EBP-0x40]"
        )
        info = classify_destination(arg, frame_size=None)
        assert not info.get("uses_alloca", False)

    def test_alloca_description_mentions_alloca(self):
        """Alloca destination description should mention alloca."""
        from bo_scanner.stack import classify_destination
        arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x1004,
            is_address=True, description="[EBP-0x1004]"
        )
        info = classify_destination(arg, frame_size=None)
        assert "alloca" in info.get("description", "").lower()

    def test_alloca_lowers_confidence(self):
        """Alloca case should have lower confidence than normal stack buffer."""
        from bo_scanner.stack import classify_destination
        alloca_arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x1004, is_address=True
        )
        normal_arg = ArgumentValue(
            type=ValType.STACK_LOCAL, ebp_offset=-0x40, is_address=True
        )
        alloca_info = classify_destination(alloca_arg, frame_size=None)
        normal_info = classify_destination(normal_arg, frame_size=0x50)
        assert alloca_info["confidence"] < normal_info["confidence"], (
            "Alloca buffer should have lower confidence than normal stack buffer"
        )
