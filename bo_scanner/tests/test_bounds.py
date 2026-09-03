"""
Tests for bounds-check detection (bounds.py).
"""
import pytest
from .conftest import make_instructions, PROLOGUE, BOUNDED_MEMCPY, MEMCPY_CALL

from bo_scanner.bounds import detect_bounds_check


class TestBoundsDetection:

    def test_detects_cmp_ja_before_call(self):
        """
        BOUNDED_MEMCPY contains:
            cmp [ebp+0x0c], 0x40
            ja  ...
            ... push args ...
            call memcpy
        Bounds check should be detected.
        """
        insns = make_instructions(PROLOGUE + BOUNDED_MEMCPY)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert result.found is True, "Expected bounds check to be detected"

    def test_no_bounds_check_without_cmp(self):
        """Plain MEMCPY_CALL has no CMP before the call."""
        insns = make_instructions(PROLOGUE + MEMCPY_CALL)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert result.found is False

    def test_evidence_populated_when_found(self):
        insns = make_instructions(PROLOGUE + BOUNDED_MEMCPY)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert result.found
        assert len(result.evidence) >= 2, "Evidence should include CMP and Jcc lines"

    def test_to_dict_structure(self):
        insns = make_instructions(PROLOGUE + BOUNDED_MEMCPY)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        d = result.to_dict()
        assert "detected" in d
        assert "evidence" in d
        assert "description" in d

    def test_bool_false_when_not_found(self):
        insns = make_instructions(PROLOGUE + MEMCPY_CALL)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert not result  # __bool__ returns self.found

    def test_bool_true_when_found(self):
        insns = make_instructions(PROLOGUE + BOUNDED_MEMCPY)
        call_idx = len(insns) - 1
        result = detect_bounds_check(insns, call_idx)
        assert result  # __bool__ returns True
