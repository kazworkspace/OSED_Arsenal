"""
Tests for risk scoring (scoring.py).

We construct synthetic CallSiteAnalysis objects and verify that:
  - Stack destination + attacker-controlled length → HIGH or CRITICAL
  - Bounds check present → lower severity than without
  - Constant source/length → lower severity
  - Unknown destination → lower severity
"""
import pytest
from bo_scanner.callsite import CallSiteAnalysis
from bo_scanner.rules import get_rule
from bo_scanner.dataflow import ValType
from bo_scanner.bounds import BoundsCheckResult
from bo_scanner.scoring import score_finding


def _make_memcpy_analysis(
    dest_type="stack",
    src_type=ValType.FUNC_ARG,
    len_type=ValType.FUNC_ARG,
    len_attacker_controlled=True,
    bounds_found=False,
    frame_size=0x40,
) -> CallSiteAnalysis:
    rule = get_rule("memcpy")
    a = CallSiteAnalysis(
        function_name="sub_00401000",
        function_start=0x401000,
        call_address=0x401050,
        api_name="memcpy",
        rule=rule,
        destination={
            "type": dest_type,
            "description": "[EBP-0x40]",
            "estimated_size": 64 if dest_type == "stack" else None,
            "size_is_upper_bound": True,
            "confidence": 0.75 if dest_type == "stack" else 0.3,
        },
        source={"type": src_type, "description": "src"},
        length={
            "type": len_type,
            "description": "len",
            "attacker_controlled": len_attacker_controlled,
        },
        bounds_check=BoundsCheckResult(found=bounds_found),
        frame_size=frame_size,
        evidence=[],
    )
    return a


class TestScoringMemcpy:

    def test_stack_dest_no_bounds_is_high_or_critical(self):
        a = _make_memcpy_analysis()
        severity, confidence = score_finding(a)
        assert severity in ("HIGH", "CRITICAL"), (
            f"Stack + attacker-controlled length + no bounds should be HIGH/CRITICAL, got {severity}"
        )

    def test_bounds_check_reduces_severity(self):
        no_bounds = _make_memcpy_analysis(bounds_found=False)
        with_bounds = _make_memcpy_analysis(bounds_found=True)
        _, c_no = score_finding(no_bounds)
        _, c_yes = score_finding(with_bounds)
        assert c_yes < c_no, (
            f"Bounds check should reduce confidence: {c_no} → {c_yes}"
        )

    def test_constant_length_reduces_severity(self):
        variable = _make_memcpy_analysis(len_type=ValType.FUNC_ARG, len_attacker_controlled=True)
        constant = _make_memcpy_analysis(len_type=ValType.IMMEDIATE, len_attacker_controlled=False)
        _, c_var = score_finding(variable)
        _, c_const = score_finding(constant)
        assert c_const < c_var, (
            f"Constant length should be lower risk: {c_var} vs {c_const}"
        )

    def test_unknown_destination_reduces_severity(self):
        stack = _make_memcpy_analysis(dest_type="stack")
        unknown = _make_memcpy_analysis(dest_type="unknown")
        _, c_stack = score_finding(stack)
        _, c_unk = score_finding(unknown)
        assert c_unk < c_stack, (
            f"Unknown destination should be lower confidence: {c_stack} vs {c_unk}"
        )

    def test_confidence_clamped_0_to_1(self):
        # Even worst case should stay in [0,1]
        a = _make_memcpy_analysis(
            dest_type="stack",
            src_type=ValType.FUNC_ARG,
            len_type=ValType.FUNC_ARG,
            len_attacker_controlled=True,
            bounds_found=False,
        )
        _, confidence = score_finding(a)
        assert 0.0 <= confidence <= 1.0

    def test_severity_labels_are_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for dest in ("stack", "global", "argument", "unknown"):
            a = _make_memcpy_analysis(dest_type=dest)
            severity, _ = score_finding(a)
            assert severity in valid, f"Unknown severity label: {severity}"


class TestScoringGets:
    """gets() has no size argument — should score HIGH regardless."""

    def test_gets_scores_high_or_critical(self):
        rule = get_rule("gets")
        a = CallSiteAnalysis(
            function_name="sub_00401100",
            function_start=0x401100,
            call_address=0x401130,
            api_name="gets",
            rule=rule,
            destination={"type": "stack", "estimated_size": 64,
                         "size_is_upper_bound": True, "confidence": 0.75,
                         "description": "[EBP-0x40]"},
            source={"type": "unknown", "description": "stdin"},
            length=None,
            bounds_check=BoundsCheckResult(found=False),
            frame_size=64,
            evidence=[],
        )
        severity, confidence = score_finding(a)
        assert severity in ("CRITICAL", "HIGH"), (
            f"gets() with stack dest should be HIGH/CRITICAL, got {severity}"
        )


class TestRulesDatabase:

    def test_memcpy_rule_exists(self):
        assert get_rule("memcpy") is not None

    def test_strcpy_rule_has_no_size_arg(self):
        rule = get_rule("strcpy")
        assert rule.size_arg is None

    def test_alias_resolves(self):
        assert get_rule("_memcpy") is get_rule("memcpy")

    def test_safe_variant_excluded(self):
        # strcpy_s and memcpy_s should return None (excluded)
        assert get_rule("strcpy_s") is None
        assert get_rule("memcpy_s") is None
