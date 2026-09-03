"""
Tests for the three enhancements:

  1. MOV [ESP+N] framestore argument recovery (GCC -O0 / MSVC calling style)
  2. Constant-size overflow detection (imm_size > est_dest → CRITICAL)
  3. Format string injection detection (CAT_FORMAT_STRING rules)
"""
import pytest
from .conftest import make_instructions

from bo_scanner.dataflow import BackwardDataFlow, ValType, ArgumentValue
from bo_scanner.stack import EspTracker, classify_destination, get_stack_frame_size
from bo_scanner.rules import get_rule, CAT_FORMAT_STRING
from bo_scanner.bounds import BoundsCheckResult
from bo_scanner.scoring import score_finding

IMAGE_BASE = 0x00400000
START_VA   = 0x00401000


# ═══════════════════════════════════════════════════════════════════
# 1.  Framestore (MOV [ESP+N]) argument recovery
# ═══════════════════════════════════════════════════════════════════
#
# Equivalent C:
#   void log_bad(char *req) {
#       char buf[0x40];
#       memcpy(buf, req, 0x50);   // overflow: 0x50 > 0x40
#   }
#
# GCC -O0 generates:
#   push  ebp
#   mov   ebp, esp
#   sub   esp, 0x40
#   lea   eax, [ebp-0x40]
#   mov   dword ptr [esp+8], 0x50    ; arg2 = size (constant, > buffer)
#   mov   dword ptr [esp+4], 0x403000 ; arg1 = src  (constant ptr)
#   mov   dword ptr [esp], eax        ; arg0 = dest = [ebp-0x40]
#   call  memcpy

FRAMESTORE_MEMCPY = bytes([
    # push ebp / mov ebp, esp / sub esp, 0x40
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40,
    # lea eax, [ebp-0x40]
    0x8D, 0x45, 0xC0,
    # mov dword ptr [esp+8], 0x50       (size = 80)
    0xC7, 0x44, 0x24, 0x08, 0x50, 0x00, 0x00, 0x00,
    # mov dword ptr [esp+4], 0x403000   (src = constant)
    0xC7, 0x44, 0x24, 0x04, 0x00, 0x30, 0x40, 0x00,
    # mov dword ptr [esp], eax          (dest = [ebp-0x40] via eax)
    0x89, 0x04, 0x24,
    # call +0
    0xE8, 0x00, 0x00, 0x00, 0x00,
])

# Same function but with [ebp+8] as source (attacker-controlled)
FRAMESTORE_ATTACKER_SRC = bytes([
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40,
    0x8D, 0x45, 0xC0,
    0xC7, 0x44, 0x24, 0x08, 0x50, 0x00, 0x00, 0x00,  # size = 0x50
    0x8B, 0x45, 0x08,                                  # mov eax, [ebp+8]  (caller arg)
    0x89, 0x44, 0x24, 0x04,                            # mov [esp+4], eax  (src = caller arg)
    0x8D, 0x45, 0xC0,                                  # lea eax, [ebp-0x40]
    0x89, 0x04, 0x24,                                  # mov [esp], eax
    0xE8, 0x00, 0x00, 0x00, 0x00,
])


class TestFramestoreRecovery:

    def _df(self, code_bytes):
        insns = make_instructions(code_bytes, START_VA)
        call_idx = len(insns) - 1
        tracker = EspTracker(insns)
        df = BackwardDataFlow(insns, call_idx, IMAGE_BASE, esp_tracker=tracker)
        return df, insns, call_idx

    def test_recovers_three_arguments(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(num_args=3)
        non_unk = [a for a in args if a.type != ValType.UNKNOWN]
        assert len(non_unk) >= 3, (
            f"Expected 3 non-UNKNOWN args, got {len(non_unk)}: "
            f"{[a.type for a in args]}"
        )

    def test_dest_is_stack_local(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        dest = args[0]
        assert dest.type == ValType.STACK_LOCAL, (
            f"Expected STACK_LOCAL, got {dest.type}: {dest.description}"
        )

    def test_dest_is_address_of(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        assert args[0].is_address is True

    def test_dest_ebp_offset_is_negative_64(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        assert args[0].ebp_offset == -0x40

    def test_src_is_immediate_constant(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        assert args[1].type == ValType.IMMEDIATE
        assert args[1].imm_value == 0x00403000

    def test_size_is_immediate_80(self):
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        assert args[2].type == ValType.IMMEDIATE
        assert args[2].imm_value == 0x50

    def test_attacker_src_is_func_arg(self):
        df, insns, _ = self._df(FRAMESTORE_ATTACKER_SRC)
        args = df.recover_arguments(3)
        assert args[1].type == ValType.FUNC_ARG, (
            f"Expected FUNC_ARG for [ebp+8] src, got {args[1].type}"
        )

    def test_push_and_framestore_merged(self):
        """Verify merge logic: non-UNKNOWN wins regardless of source."""
        df, insns, _ = self._df(FRAMESTORE_MEMCPY)
        args = df.recover_arguments(3)
        # All 3 args should be non-UNKNOWN — framestore fills them all
        assert all(a.type != ValType.UNKNOWN for a in args[:3]), (
            f"Expected all 3 args non-UNKNOWN, got {[a.type for a in args[:3]]}"
        )


class TestFramestoreWithIntermediateCall:
    """
    Mimic log_bad_request: memset call between slot setup and memcpy call.
    Slot 8 (size) is set, then CALL memset happens, then slots 0 and 4 are set.
    The framestore scanner should find all 3 slots (it doesn't stop at CALL).
    """

    # sub esp, 0x808
    # lea eax, [ebp-0x808]
    # mov [esp], eax           ; memset dest
    # call memset              ; <-- intermediate call
    # mov [esp+8], 0x4000      ; memcpy size
    # mov eax, [ebp+8]         ; src from caller
    # mov [esp+4], eax
    # lea eax, [ebp-0x808]
    # mov [esp], eax           ; memcpy dest
    # call memcpy
    LOG_BAD_REQUEST = bytes([
        # prologue
        0x55, 0x8B, 0xEC,
        # sub esp, 0x808  (imm32)
        0x81, 0xEC, 0x08, 0x08, 0x00, 0x00,
        # lea eax, [ebp-0x808]  → 8D 85 F8 F7 FF FF
        0x8D, 0x85, 0xF8, 0xF7, 0xFF, 0xFF,
        # mov [esp], eax
        0x89, 0x04, 0x24,
        # call placeholder (memset)
        0xE8, 0x00, 0x00, 0x00, 0x00,
        # mov [esp+8], 0x4000
        0xC7, 0x44, 0x24, 0x08, 0x00, 0x40, 0x00, 0x00,
        # mov eax, [ebp+8]
        0x8B, 0x45, 0x08,
        # mov [esp+4], eax
        0x89, 0x44, 0x24, 0x04,
        # lea eax, [ebp-0x808]
        0x8D, 0x85, 0xF8, 0xF7, 0xFF, 0xFF,
        # mov [esp], eax
        0x89, 0x04, 0x24,
        # call memcpy
        0xE8, 0x00, 0x00, 0x00, 0x00,
    ])

    def setup_method(self):
        self.insns = make_instructions(self.LOG_BAD_REQUEST, START_VA)
        self.call_idx = len(self.insns) - 1
        tracker = EspTracker(self.insns)
        df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE, esp_tracker=tracker)
        self.args = df.recover_arguments(3)

    def test_dest_is_stack_local(self):
        assert self.args[0].type == ValType.STACK_LOCAL, (
            f"Expected STACK_LOCAL, got {self.args[0].type}: {self.args[0].description}"
        )

    def test_src_is_caller_arg(self):
        assert self.args[1].type == ValType.FUNC_ARG, (
            f"Expected FUNC_ARG, got {self.args[1].type}: {self.args[1].description}"
        )

    def test_size_is_constant_0x4000(self):
        assert self.args[2].type == ValType.IMMEDIATE, (
            f"Expected IMMEDIATE for size, got {self.args[2].type}"
        )
        assert self.args[2].imm_value == 0x4000, (
            f"Expected 0x4000, got {self.args[2].imm_value}"
        )


# ═══════════════════════════════════════════════════════════════════
# 2.  Constant-size overflow detection
# ═══════════════════════════════════════════════════════════════════

def _memcpy_analysis(dest_size, imm_size=None, len_type=ValType.FUNC_ARG,
                     attacker=True, bounds=False):
    """Build a synthetic CallSiteAnalysis for scoring tests."""
    from bo_scanner.callsite import CallSiteAnalysis
    rule = get_rule("memcpy")
    return CallSiteAnalysis(
        function_name="sub_401000", function_start=0x401000,
        call_address=0x401050, api_name="memcpy", rule=rule,
        destination={
            "type": "stack" if dest_size else "unknown",
            "estimated_size": dest_size,
            "size_is_upper_bound": True,
            "confidence": 0.75,
            "description": f"[EBP-0x{dest_size:X}]" if dest_size else "unknown",
        },
        source={"type": ValType.FUNC_ARG, "description": "src"},
        length={
            "type": len_type,
            "description": f"0x{imm_size:X}" if imm_size else "arg",
            "imm_value": imm_size,
            "attacker_controlled": attacker,
        },
        bounds_check=BoundsCheckResult(found=bounds),
    )


class TestConstantOverflow:

    def test_hardcoded_overflow_4x_is_critical(self):
        """0x4000 into 0x808-byte buffer (8×) → CRITICAL."""
        a = _memcpy_analysis(dest_size=0x808, imm_size=0x4000,
                             len_type=ValType.IMMEDIATE, attacker=False)
        severity, conf = score_finding(a)
        assert severity == "CRITICAL", (
            f"0x4000 into 0x808 buffer should be CRITICAL, got {severity} ({conf:.0%})"
        )

    def test_hardcoded_overflow_2x_is_high_or_critical(self):
        """0x80 into 0x40-byte buffer (2×) → HIGH or CRITICAL."""
        a = _memcpy_analysis(dest_size=0x40, imm_size=0x80,
                             len_type=ValType.IMMEDIATE, attacker=False)
        severity, conf = score_finding(a)
        assert severity in ("HIGH", "CRITICAL"), (
            f"2× overflow should be HIGH/CRITICAL, got {severity}"
        )

    def test_hardcoded_overflow_is_critical_even_without_attacker_source(self):
        """
        Constant overflow with a non-attacker-controlled source should still
        be CRITICAL — the overflow is provable regardless of source provenance.
        """
        # Source is a constant (normally reduces score), but overflow is huge
        a = _memcpy_analysis(dest_size=0x40, imm_size=0x4000,
                             len_type=ValType.IMMEDIATE, attacker=False)
        severity, _ = score_finding(a)
        assert severity == "CRITICAL", (
            f"Provable 8× overflow should be CRITICAL even with constant source, "
            f"got {severity}"
        )

    def test_constant_overflow_scores_higher_than_constant_within_bounds(self):
        """
        Same function, same constant size but different buffer size:
        overflowing should score higher than fitting.
        """
        overflow = _memcpy_analysis(dest_size=0x20, imm_size=0x40,
                                    len_type=ValType.IMMEDIATE, attacker=False)
        fits     = _memcpy_analysis(dest_size=0x80, imm_size=0x40,
                                    len_type=ValType.IMMEDIATE, attacker=False)
        _, c_ov   = score_finding(overflow)
        _, c_fits = score_finding(fits)
        assert c_ov > c_fits, (
            f"Overflowing copy ({c_ov:.0%}) should score higher than "
            f"fitting copy ({c_fits:.0%})"
        )

    def test_constant_within_bounds_is_lower_than_overflow(self):
        """0x30 into 0x40 buffer: fits → lower risk than overflow."""
        safe = _memcpy_analysis(dest_size=0x40, imm_size=0x30,
                                len_type=ValType.IMMEDIATE, attacker=False)
        overflow = _memcpy_analysis(dest_size=0x40, imm_size=0x80,
                                    len_type=ValType.IMMEDIATE, attacker=False)
        _, c_safe = score_finding(safe)
        _, c_ov   = score_finding(overflow)
        assert c_ov > c_safe, (
            f"Overflow ({c_ov:.0%}) should score higher than safe copy ({c_safe:.0%})"
        )

    def test_overflow_ratio_in_json(self):
        """JSON report should include constant_overflow flag and ratio."""
        from bo_scanner.report import _finding_to_dict
        a = _memcpy_analysis(dest_size=0x808, imm_size=0x4000,
                             len_type=ValType.IMMEDIATE, attacker=False)
        a.severity, a.confidence = score_finding(a)
        d = _finding_to_dict(a)
        ldict = d.get("length", {}) or {}
        assert ldict.get("constant_overflow") is True
        assert ldict.get("overflow_ratio") is not None
        assert ldict["overflow_ratio"] > 4.0


# ═══════════════════════════════════════════════════════════════════
# 3.  Format string injection detection
# ═══════════════════════════════════════════════════════════════════

class TestFormatStringRules:

    def test_snprintf_rule_exists(self):
        rule = get_rule("snprintf")
        assert rule is not None
        assert rule.category == CAT_FORMAT_STRING

    def test_snprintf_format_arg_is_2(self):
        rule = get_rule("snprintf")
        assert rule.format_arg == 2    # snprintf(buf, n, FMT, ...)

    def test_printf_format_arg_is_0(self):
        rule = get_rule("printf")
        assert rule.format_arg == 0    # printf(FMT, ...)

    def test_fprintf_format_arg_is_1(self):
        rule = get_rule("fprintf")
        assert rule.format_arg == 1    # fprintf(file, FMT, ...)

    def test_snprintf_alias_resolved(self):
        rule = get_rule("_snprintf")
        assert rule is not None
        assert rule.name == "snprintf"


class TestFormatStringScoringUserControlled:
    """snprintf with user-controlled format → HIGH or CRITICAL."""

    def _fmt_analysis(self, fmt_type, fmt_attacker=False, fmt_constant=False):
        from bo_scanner.callsite import CallSiteAnalysis
        rule = get_rule("snprintf")
        return CallSiteAnalysis(
            function_name="sub_401000", function_start=0x401000,
            call_address=0x401050, api_name="snprintf", rule=rule,
            destination={"type": "stack", "estimated_size": 0x800,
                         "confidence": 0.75, "description": "buf"},
            source={"type": "unknown", "description": ""},
            length={"type": ValType.IMMEDIATE, "imm_value": 0x800,
                    "description": "0x800", "attacker_controlled": False},
            format_string={
                "type": fmt_type,
                "description": "format arg",
                "attacker_controlled": fmt_attacker,
                "is_constant": fmt_constant,
                "is_global": fmt_type == ValType.GLOBAL,
            },
            bounds_check=BoundsCheckResult(found=False),
        )

    def test_user_controlled_format_is_high_or_critical(self):
        a = self._fmt_analysis(ValType.FUNC_ARG, fmt_attacker=True)
        severity, conf = score_finding(a)
        assert severity in ("HIGH", "CRITICAL"), (
            f"User-controlled format should be HIGH/CRITICAL, got {severity} ({conf:.0%})"
        )

    def test_constant_format_is_low_or_info(self):
        a = self._fmt_analysis(ValType.IMMEDIATE, fmt_constant=True)
        severity, conf = score_finding(a)
        assert severity in ("LOW", "INFO", "MEDIUM"), (
            f"Constant format should be low risk, got {severity} ({conf:.0%})"
        )

    def test_user_controlled_scores_higher_than_constant(self):
        user = self._fmt_analysis(ValType.FUNC_ARG, fmt_attacker=True)
        const = self._fmt_analysis(ValType.IMMEDIATE, fmt_constant=True)
        _, c_user  = score_finding(user)
        _, c_const = score_finding(const)
        assert c_user > c_const, (
            f"User-controlled format ({c_user:.0%}) should score higher "
            f"than constant ({c_const:.0%})"
        )


class TestFormatStringInBinary:
    """
    Synthetic byte sequence for snprintf(buf, 0x800, user_fmt):
      push  ebp
      mov   ebp, esp
      sub   esp, 0x40
      lea   eax, [ebp-0x40]          ; dest buf
      mov   [esp+8], dword [ebp+8]   ; fmt = caller's arg (attacker-controlled)
      mov   [esp+4], 0x800           ; size
      mov   [esp], eax               ; dest
      call  snprintf
    """
    SNPRINTF_USER_FMT = bytes([
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40,
        # lea eax, [ebp-0x40]
        0x8D, 0x45, 0xC0,
        # mov [esp+8], dword ptr [ebp+8]  (format = caller arg0)
        0x8B, 0x45, 0x08,                # mov eax, [ebp+8]
        0x89, 0x44, 0x24, 0x08,          # mov [esp+8], eax
        # mov [esp+4], 0x800
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x08, 0x00, 0x00,
        # lea eax, [ebp-0x40]
        0x8D, 0x45, 0xC0,
        # mov [esp], eax
        0x89, 0x04, 0x24,
        # call +0
        0xE8, 0x00, 0x00, 0x00, 0x00,
    ])

    def setup_method(self):
        self.insns = make_instructions(self.SNPRINTF_USER_FMT, START_VA)
        self.call_idx = len(self.insns) - 1
        tracker = EspTracker(self.insns)
        df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE,
                              esp_tracker=tracker)
        self.args = df.recover_arguments(num_args=4)  # snprintf(dest, size, fmt, ...)

    def test_dest_recovered(self):
        assert self.args[0].type == ValType.STACK_LOCAL

    def test_size_is_constant(self):
        assert self.args[1].type == ValType.IMMEDIATE
        assert self.args[1].imm_value == 0x800

    def test_format_is_caller_arg(self):
        """Format arg (index 2) should resolve to FUNC_ARG (caller-controlled)."""
        assert self.args[2].type == ValType.FUNC_ARG, (
            f"Expected FUNC_ARG for format, got {self.args[2].type}: "
            f"{self.args[2].description}"
        )
