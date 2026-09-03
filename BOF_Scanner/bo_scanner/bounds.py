"""
Bounds-check detection.

Enhanced to distinguish:
  - Unsigned comparisons (JA/JAE/JB/JBE): semantically correct for size checks
  - Signed comparisons (JG/JGE/JL/JLE): potentially bypassable via negative integers
  - Flag-only (JE/JNE etc.): semantic depends on what was compared

Signed comparison risk:
    if length is compared with JL/JLE (signed), a negative value satisfies
    the check — e.g. JL reject with length=-1 passes, then -1 is used as
    a size_t (wrapping to 0xFFFFFFFF bytes to copy).
"""
from dataclasses import dataclass, field
from typing import List, Optional

from .disassembler import Instruction


# Unsigned comparisons — semantically correct for size/count bounds
_JCC_UNSIGNED = frozenset({
    "ja", "jae",   # jump if above / above-or-equal  (CF=0, CF=0|ZF=1)
    "jb", "jbe",   # jump if below / below-or-equal  (CF=1, CF=1|ZF=1)
})

# Signed comparisons — dangerous on size values; negative input bypasses check
_JCC_SIGNED = frozenset({
    "jg", "jge",   # jump if greater / greater-or-equal  (ZF=0|SF=OF, SF=OF)
    "jl", "jle",   # jump if less / less-or-equal        (SF≠OF, ZF=1|SF≠OF)
})

# Flag-only — semantics depend on context; ambiguous for bounds reasoning
_JCC_FLAG = frozenset({
    "je", "jz",    # jump if equal / zero
    "jne", "jnz",  # jump if not equal / not zero
    "js", "jns",   # jump if sign / not sign
    "jo", "jno",   # jump if overflow / not overflow
    "jp", "jpe", "jpo",  # parity
    "jecxz",       # jump if ECX == 0
})

_ALL_JCC = _JCC_UNSIGNED | _JCC_SIGNED | _JCC_FLAG


def _classify_jcc(mnemonic: str) -> str:
    if mnemonic in _JCC_UNSIGNED:
        return "unsigned"
    if mnemonic in _JCC_SIGNED:
        return "signed"
    if mnemonic in _JCC_FLAG:
        return "flag_only"
    return "unknown"


@dataclass
class BoundsCheckResult:
    found: bool
    evidence: List[str] = field(default_factory=list)
    description: str = "No bounds check detected in lookback window"
    jcc_type: Optional[str] = None   # "unsigned" | "signed" | "flag_only" | None
    signed_risk: bool = False         # True when signed Jcc — negative input may bypass

    def __bool__(self) -> bool:
        return self.found

    def to_dict(self) -> dict:
        d = {
            "detected": self.found,
            "description": self.description,
            "evidence": self.evidence,
        }
        if self.found:
            d["comparison_type"] = self.jcc_type
            d["signed_integer_bypass_risk"] = self.signed_risk
        return d


def detect_bounds_check(
    instructions: List[Instruction],
    call_index: int,
    max_lookback: int = 25,
) -> BoundsCheckResult:
    """
    Scan backward from a dangerous call for a CMP/TEST + Jcc pattern.

    Returns BoundsCheckResult with:
      found        - True if a CMP+Jcc pair was detected
      jcc_type     - "unsigned" | "signed" | "flag_only"
      signed_risk  - True if Jcc is signed (JG/JGE/JL/JLE); negative input may bypass
      evidence     - [cmp_line, jcc_line]

    A signed bounds check on a size value is a known vulnerability pattern:
      cmp [ebp+0Ch], 0x200   ; compare length
      jle accept             ; JLE (signed) → passes if length is negative
      ...
    The length -1 (0xFFFFFFFF as unsigned) passes the check and causes overflow.
    """
    scan_start = max(0, call_index - max_lookback)
    window = instructions[scan_start:call_index]

    for i, insn in enumerate(window):
        if not insn.is_cmp_or_test:
            continue

        for j in range(i + 1, min(i + 4, len(window))):
            nxt = window[j]
            if nxt.mnemonic not in _ALL_JCC:
                continue

            jcc_type = _classify_jcc(nxt.mnemonic)
            signed_risk = (jcc_type == "signed")
            evidence = [insn.full_str, nxt.full_str]

            if signed_risk:
                desc = (
                    f"Potential bounds check — SIGNED comparison: "
                    f"{insn.mnemonic.upper()} at 0x{insn.address:08X} "
                    f"→ {nxt.mnemonic.upper()} at 0x{nxt.address:08X}. "
                    f"WARNING: {nxt.mnemonic.upper()} is a signed branch; "
                    f"a negative size value satisfies this check and wraps to a "
                    f"large unsigned count. Manual review required."
                )
            else:
                desc = (
                    f"Potential bounds check ({jcc_type}): "
                    f"{insn.mnemonic.upper()} at 0x{insn.address:08X} "
                    f"→ {nxt.mnemonic.upper()} at 0x{nxt.address:08X}. "
                    f"NOTE: check may or may not apply to the relevant size argument."
                )

            return BoundsCheckResult(
                found=True,
                evidence=evidence,
                description=desc,
                jcc_type=jcc_type,
                signed_risk=signed_risk,
            )

    return BoundsCheckResult(found=False)
