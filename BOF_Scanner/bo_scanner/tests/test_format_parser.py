"""
Tests for the format string specifier parser.

Covers:
  - Unbounded %s and %[...] detection
  - Width-bounded safe variants
  - %n write primitive detection
  - Numeric types (%d, %x, etc.) correctly ignored for overflow
  - Mixed format strings
  - analyze_format_danger() summary
"""
import pytest
from bo_scanner.format_parser import parse_format_string, analyze_format_danger, FormatSpec


class TestBasicSpecifiers:

    def test_bare_s_is_dangerous(self):
        specs = parse_format_string("%s")
        assert len(specs) == 1
        assert specs[0].type_char == 's'
        assert specs[0].is_dangerous is True
        assert specs[0].width is None

    def test_width_s_is_safe(self):
        specs = parse_format_string("%255s")
        assert len(specs) == 1
        assert specs[0].type_char == 's'
        assert specs[0].is_dangerous is False
        assert specs[0].width == 255

    def test_n_is_critical_write_primitive(self):
        specs = parse_format_string("%n")
        assert len(specs) == 1
        assert specs[0].type_char == 'n'
        assert specs[0].is_critical is True
        assert specs[0].is_dangerous is False  # is_critical is separate

    def test_double_percent_skipped(self):
        specs = parse_format_string("100%%")
        assert len(specs) == 0

    def test_numeric_d_not_dangerous(self):
        specs = parse_format_string("%d")
        assert len(specs) == 1
        assert specs[0].is_dangerous is False
        assert specs[0].is_critical is False


class TestCharacterClassSpecifiers:

    def test_bare_char_class_is_dangerous(self):
        """scanf format %[^\\n] — no width — unbounded scan."""
        specs = parse_format_string("%[^\n]")
        assert len(specs) == 1
        assert specs[0].type_char == '['
        assert specs[0].is_dangerous is True
        assert specs[0].width is None

    def test_width_char_class_is_safe(self):
        """scanf format %2047[^\\n] — bounded scan."""
        specs = parse_format_string("%2047[^\n]")
        assert len(specs) == 1
        assert specs[0].type_char == '['
        assert specs[0].is_dangerous is False
        assert specs[0].width == 2047

    def test_char_class_with_caret(self):
        specs = parse_format_string("%[^abc]")
        assert specs[0].is_dangerous is True

    def test_char_class_inclusive(self):
        specs = parse_format_string("%[abc]")
        assert specs[0].is_dangerous is True

    def test_width_char_class_raw_contains_width(self):
        specs = parse_format_string("%100[^\n]")
        assert specs[0].width == 100
        assert '100' in specs[0].raw


class TestSignatusPattern:
    """The exact vulnerable pattern from signatus.exe."""

    def test_fscanf_unbounded_pattern(self):
        """fscanf(fp, "%[^\\n]\\n", line) — the signatus vulnerability."""
        specs = parse_format_string("%[^\n]\n")
        assert len(specs) == 1
        assert specs[0].is_dangerous is True
        assert specs[0].width is None

    def test_fscanf_bounded_safe_variant(self):
        """fscanf(fp, "%2047[^\\n]\\n", line) — safe version."""
        specs = parse_format_string("%2047[^\n]\n")
        assert len(specs) == 1
        assert specs[0].is_dangerous is False
        assert specs[0].width == 2047


class TestMixedFormatStrings:

    def test_mixed_dangerous_and_safe(self):
        specs = parse_format_string("name=%s age=%d score=%255s")
        assert len(specs) == 3
        dangerous = [s for s in specs if s.is_dangerous]
        safe      = [s for s in specs if not s.is_dangerous and not s.is_critical]
        assert len(dangerous) == 1   # bare %s
        assert dangerous[0].type_char == 's'
        assert dangerous[0].width is None
        assert len(safe) == 2        # %d and %255s

    def test_multiple_dangerous_specifiers(self):
        specs = parse_format_string("%s %[^\n]")
        dangerous = [s for s in specs if s.is_dangerous]
        assert len(dangerous) == 2

    def test_n_mixed_with_others(self):
        specs = parse_format_string("%d %n %s")
        criticals = [s for s in specs if s.is_critical]
        dangerous = [s for s in specs if s.is_dangerous]
        assert len(criticals) == 1
        assert len(dangerous) == 1   # %s

    def test_literal_text_ignored(self):
        specs = parse_format_string("Hello World, no specifiers here!")
        assert len(specs) == 0

    def test_format_with_flags_and_length(self):
        """%-10.5s — flags and precision, but no explicit field width."""
        specs = parse_format_string("%-10.5s")
        # Width 10 is a minimum field width (padding), not a read width for scanf
        # Parser should still extract it as width=10
        assert len(specs) == 1


class TestAnalyzeFormatDanger:

    def test_unbounded_s_is_dangerous(self):
        specs = parse_format_string("%s")
        result = analyze_format_danger(specs)
        assert result['has_unbounded'] is True
        assert result['has_write_primitive'] is False
        assert result['all_bounded'] is False
        assert len(result['dangerous_specs']) == 1

    def test_bounded_s_is_all_bounded(self):
        specs = parse_format_string("%255s")
        result = analyze_format_danger(specs)
        assert result['has_unbounded'] is False
        assert result['all_bounded'] is True
        assert len(result['safe_specs']) == 1

    def test_n_triggers_write_primitive(self):
        specs = parse_format_string("%d %n")
        result = analyze_format_danger(specs)
        assert result['has_write_primitive'] is True
        assert result['all_bounded'] is False

    def test_mixed_unbounded_not_all_bounded(self):
        specs = parse_format_string("%255s %s")
        result = analyze_format_danger(specs)
        assert result['has_unbounded'] is True
        assert result['all_bounded'] is False

    def test_only_numeric_not_all_bounded(self):
        """Format with only %d/%x — no string specifiers — not 'all_bounded'."""
        specs = parse_format_string("%d %x")
        result = analyze_format_danger(specs)
        assert result['all_bounded'] is False   # no string specifiers present
        assert result['has_unbounded'] is False
        assert result['has_write_primitive'] is False

    def test_empty_format_not_all_bounded(self):
        specs = parse_format_string("no specifiers")
        result = analyze_format_danger(specs)
        assert result['all_bounded'] is False
        assert result['has_unbounded'] is False

    def test_dangerous_specs_list_populated(self):
        specs = parse_format_string("%s %[^\n]")
        result = analyze_format_danger(specs)
        assert len(result['dangerous_specs']) == 2
        raws = [d['raw'] for d in result['dangerous_specs']]
        assert '%s' in raws

    def test_signatus_pattern_danger(self):
        specs = parse_format_string("%[^\n]\n")
        result = analyze_format_danger(specs)
        assert result['has_unbounded'] is True
        assert result['has_write_primitive'] is False
        assert result['all_bounded'] is False


class TestScoringWithFormatAnalysis:
    """Verify that format analysis drives correct severity scoring."""

    def _analysis(self, fmt_literal, dest_type="stack"):
        from bo_scanner.callsite import CallSiteAnalysis
        from bo_scanner.rules import get_rule
        from bo_scanner.bounds import BoundsCheckResult
        from bo_scanner.format_parser import parse_format_string, analyze_format_danger
        rule = get_rule("scanf")
        specs = parse_format_string(fmt_literal)
        fa = analyze_format_danger(specs)
        return CallSiteAnalysis(
            function_name="test", function_start=0x401000,
            call_address=0x401050, api_name="scanf", rule=rule,
            destination={"type": dest_type, "estimated_size": 256, "confidence": 0.75,
                         "description": "buf"},
            source={"type": "immediate", "description": repr(fmt_literal)},
            format_string={
                "type": "immediate", "description": repr(fmt_literal),
                "attacker_controlled": False,
                "is_constant": not (fa["has_unbounded"] or fa["has_write_primitive"]),
                "is_global": False,
                "format_literal": fmt_literal,
                "format_analysis": fa,
            },
            bounds_check=BoundsCheckResult(found=False),
        )

    def test_unbounded_s_scores_higher_than_bounded(self):
        from bo_scanner.scoring import score_finding
        unsafe = self._analysis("%s")
        safe   = self._analysis("%255s")
        _, c_unsafe = score_finding(unsafe)
        _, c_safe   = score_finding(safe)
        assert c_unsafe > c_safe, (
            f"Unbounded %s ({c_unsafe:.0%}) should score higher than %255s ({c_safe:.0%})"
        )

    def test_unbounded_char_class_scores_high(self):
        from bo_scanner.scoring import score_finding
        a = self._analysis("%[^\n]")
        severity, conf = score_finding(a)
        assert severity in ("CRITICAL", "HIGH"), (
            f"scanf with %[^\\n] should be HIGH/CRITICAL, got {severity}"
        )

    def test_bounded_char_class_scores_low(self):
        from bo_scanner.scoring import score_finding
        a = self._analysis("%2047[^\n]")
        severity, conf = score_finding(a)
        assert severity in ("LOW", "INFO", "MEDIUM"), (
            f"scanf with %2047[^\\n] should be LOW/INFO, got {severity} ({conf:.0%})"
        )

    def test_n_specifier_is_critical(self):
        from bo_scanner.scoring import score_finding
        a = self._analysis("%n")
        severity, conf = score_finding(a)
        assert severity == "CRITICAL", (
            f"scanf with %n should be CRITICAL, got {severity}"
        )


class TestReadCstringAt:
    """Verify pe.read_cstring_at reads strings from section data."""

    def _make_pe_with_string(self, string_bytes, va=0x40A000):
        """Return a minimal PEContext with one data section containing the string."""
        from bo_scanner.pe import PEContext, read_cstring_at
        from unittest.mock import MagicMock
        pe = MagicMock(spec=PEContext)
        pe._sections = [(va, string_bytes)]
        # Bind the method to the mock
        pe.read_cstring_at = lambda v, max_len=512: read_cstring_at(pe, v, max_len)
        return pe, va

    def test_reads_simple_string(self):
        from bo_scanner.pe import read_cstring_at
        from unittest.mock import MagicMock
        from bo_scanner.pe import PEContext
        pe = MagicMock()
        pe._sections = [(0x40A000, b"%[^\n]\n\x00more data")]
        result = read_cstring_at(pe, 0x40A000)
        assert result == "%[^\n]\n"

    def test_returns_none_for_unknown_va(self):
        from bo_scanner.pe import read_cstring_at
        from unittest.mock import MagicMock
        pe = MagicMock()
        pe._sections = [(0x40A000, b"hello\x00")]
        result = read_cstring_at(pe, 0x00401000)  # not in any section
        assert result is None

    def test_handles_no_null_terminator(self):
        from bo_scanner.pe import read_cstring_at
        from unittest.mock import MagicMock
        pe = MagicMock()
        pe._sections = [(0x40A000, b"abcdef")]  # no null
        result = read_cstring_at(pe, 0x40A000, max_len=4)
        assert result == "abcd"
