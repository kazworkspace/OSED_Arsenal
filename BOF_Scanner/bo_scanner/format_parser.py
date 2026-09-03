"""
Format string specifier parser.

Parses C printf/scanf format strings and identifies dangerous patterns:

  %s         — unbounded string read/write — DANGEROUS
  %[^\n]     — unbounded character class scan — DANGEROUS
  %n         — writes an integer to a pointer argument — CRITICAL (write primitive)
  %255s      — width-bounded string — SAFE
  %255[^\n]  — width-bounded character class — SAFE

Used to analyse the content of constant format strings found at compile-time
addresses (e.g. scanf(fp, "%[^\n]\\n", buf) where "%[^\\n]\\n" is in .rdata).

This is separate from detecting whether the FORMAT ARGUMENT itself is
user-controlled (which is a different vulnerability class).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import re


@dataclass(frozen=True)
class FormatSpec:
    """One parsed format specifier from a format string."""
    raw: str                  # the full specifier, e.g. "%s", "%255[^\n]"
    type_char: str            # conversion character: 's', '[', 'n', 'd', …
    width: Optional[int]      # explicit width, or None if absent
    is_dangerous: bool        # unbounded %s or %[…] that can overflow the dest
    is_critical: bool         # %n — enables arbitrary memory write
    reason: str               # human-readable explanation


# Conversion characters that are dangerous for buffer overflow when unbounded
_OVERFLOW_TYPES = frozenset({'s', '['})

# Conversion characters that are write primitives regardless of width
_WRITE_PRIMITIVE = frozenset({'n'})

# Conversion characters that are safe for buffer overflow (numeric / pointer)
_SAFE_TYPES = frozenset({'d', 'i', 'o', 'u', 'x', 'X',
                          'e', 'E', 'f', 'F', 'g', 'G',
                          'a', 'A', 'c', 'p', '%'})


def parse_format_string(fmt: str) -> List[FormatSpec]:
    """
    Parse every format specifier in a C format string.

    Returns a list of FormatSpec objects in order of appearance.
    Unrecognised bytes are skipped conservatively.

    Examples
    --------
    parse_format_string("%s")            → [FormatSpec('%s', 's', None, True, False, …)]
    parse_format_string("%255s")         → [FormatSpec('%255s', 's', 255, False, False, …)]
    parse_format_string("%[^\\n]")       → [FormatSpec('%[^\\n]', '[', None, True, False, …)]
    parse_format_string("%255[^\\n]")    → [FormatSpec('%255[^\\n]', '[', 255, False, False, …)]
    parse_format_string("%n")            → [FormatSpec('%n', 'n', None, False, True, …)]
    parse_format_string("value=%d\\n")   → [FormatSpec('%d', 'd', None, False, False, …)]
    """
    specs: List[FormatSpec] = []
    i = 0

    while i < len(fmt):
        if fmt[i] != '%':
            i += 1
            continue

        start = i
        i += 1          # skip '%'

        if i >= len(fmt):
            break

        # Literal %%
        if fmt[i] == '%':
            i += 1
            continue

        # ── Flags ────────────────────────────────────────────────────────────
        while i < len(fmt) and fmt[i] in '-+ #0*':
            i += 1

        # ── Width ────────────────────────────────────────────────────────────
        width: Optional[int] = None
        if i < len(fmt) and fmt[i] == '*':
            # Width from argument — treat as unbounded (runtime value)
            i += 1
        else:
            width_start = i
            while i < len(fmt) and fmt[i].isdigit():
                i += 1
            if i > width_start:
                width = int(fmt[width_start:i])

        # ── Precision ────────────────────────────────────────────────────────
        if i < len(fmt) and fmt[i] == '.':
            i += 1
            if i < len(fmt) and fmt[i] == '*':
                i += 1
            else:
                while i < len(fmt) and fmt[i].isdigit():
                    i += 1

        # ── Length modifier ──────────────────────────────────────────────────
        if i < len(fmt) and fmt[i:i+2] in ('hh', 'll', 'Lq'):
            i += 2
        elif i < len(fmt) and fmt[i] in 'hlLqjzt':
            i += 1

        if i >= len(fmt):
            break

        # ── Conversion type ──────────────────────────────────────────────────
        type_char = fmt[i]
        i += 1

        # Build raw specifier string
        raw = fmt[start:i]

        # ── Character class %[…] ─────────────────────────────────────────────
        if type_char == '[':
            class_start = i
            if i < len(fmt) and fmt[i] == '^':
                i += 1
            if i < len(fmt) and fmt[i] == ']':
                i += 1   # allow ] as first char in class
            while i < len(fmt) and fmt[i] != ']':
                i += 1
            if i < len(fmt):
                i += 1   # skip closing ]
            raw = fmt[start:i]

        # ── Classify ─────────────────────────────────────────────────────────
        is_critical  = type_char in _WRITE_PRIMITIVE
        is_dangerous = False
        reason = ""

        if is_critical:
            reason = (
                "%n writes the number of bytes printed so far to a pointer argument "
                "— enables arbitrary memory write"
            )
        elif type_char in _OVERFLOW_TYPES:
            if width is None:
                is_dangerous = True
                if type_char == 's':
                    reason = "%s without width specifier — unbounded string read/write"
                else:
                    reason = "%[…] without width specifier — unbounded character class scan"
            else:
                reason = f"width-bounded (max {width} chars) — safe if destination ≥ {width + 1} bytes"
        elif type_char in _SAFE_TYPES:
            reason = f"%{type_char} — numeric/pointer conversion, not a buffer overflow vector"
        else:
            reason = f"%{type_char} — unknown conversion type"

        specs.append(FormatSpec(
            raw=raw,
            type_char=type_char,
            width=width,
            is_dangerous=is_dangerous,
            is_critical=is_critical,
            reason=reason,
        ))

    return specs


def analyze_format_danger(specs: List[FormatSpec]) -> Dict:
    """
    Summarise the danger level of a list of parsed format specifiers.

    Returns a dict with:
        has_write_primitive  bool   — any %n found
        has_unbounded        bool   — any unbounded %s or %[…]
        all_bounded          bool   — every string specifier has an explicit width
        dangerous_specs      list   — [{'raw', 'reason'}, …] for each dangerous/critical spec
        safe_specs           list   — [{'raw', 'reason'}, …] for each bounded spec
    """
    dangerous: List[Dict] = []
    safe: List[Dict] = []

    has_write_primitive = False
    has_unbounded = False
    string_spec_count = 0
    bounded_string_count = 0

    for spec in specs:
        if spec.is_critical:
            has_write_primitive = True
            dangerous.append({'raw': spec.raw, 'reason': spec.reason})
        elif spec.is_dangerous:
            has_unbounded = True
            string_spec_count += 1
            dangerous.append({'raw': spec.raw, 'reason': spec.reason})
        elif spec.type_char in _OVERFLOW_TYPES:
            string_spec_count += 1
            bounded_string_count += 1
            safe.append({'raw': spec.raw, 'reason': spec.reason})

    all_bounded = (
        not has_write_primitive
        and not has_unbounded
        and string_spec_count > 0
        and bounded_string_count == string_spec_count
    )

    return {
        'has_write_primitive': has_write_primitive,
        'has_unbounded': has_unbounded,
        'all_bounded': all_bounded,
        'dangerous_specs': dangerous,
        'safe_specs': safe,
    }
