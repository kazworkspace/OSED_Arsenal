"""
Risk scoring and severity classification.

New in this version:
  - Constant overflow detection: if imm_size > est_dest_size → escalate to CRITICAL
  - Format string scoring: CAT_FORMAT_STRING with user-controlled format → HIGH/CRITICAL
  - Signed bounds check: -5 credit instead of -22 (bypassable)
  - FUNC_ARG_REGISTER treated same as FUNC_ARG for risk
"""
from typing import List, Tuple

from .callsite import CallSiteAnalysis
from .dataflow import ValType
from .rules import (
    CAT_UNBOUNDED_COPY, CAT_SIZE_DEPENDENT, CAT_FORMATTED_INPUT,
    CAT_FORMAT_STRING, CAT_INDIRECT_UNRESOLVED,
)
# CAT_FORMATTED_INPUT shares the format-string scoring path — both analyse
# whether the format specifier is dangerous (e.g. %s vs %255s)

_CALLER_CONTROLLED = {ValType.FUNC_ARG, ValType.FUNC_ARG_REGISTER}


def score_finding(analysis: CallSiteAnalysis) -> Tuple[str, float]:
    """
    Compute (severity: str, confidence: float 0.0–1.0).

    Severity scale:
        CRITICAL  ≥85   Potential Buffer Overflow (exploitability near-certain)
        HIGH      ≥65   Likely Unsafe Memory Copy
        MEDIUM    ≥42   Suspicious API Usage
        LOW       ≥18   Suspicious API Usage (low confidence)
        INFO      <18   Insufficient Bounds Evidence
    """
    rule = analysis.rule

    if rule.category == CAT_INDIRECT_UNRESOLVED:
        return "INFO", 0.05

    dest = analysis.destination
    src  = analysis.source
    leng = analysis.length
    bc   = analysis.bounds_check
    fmt  = analysis.format_string

    # ── Format string category: separate scoring path ─────────────────────────
    if rule.category in (CAT_FORMAT_STRING, CAT_FORMATTED_INPUT):
        score = rule.base_risk
        fmt_analysis = (fmt or {}).get("format_analysis", {}) if fmt else {}

        if fmt is not None:
            if fmt.get("attacker_controlled"):
                # Runtime-controlled format string — classic format string vuln
                score += 20

            elif fmt_analysis.get("has_write_primitive"):
                # Constant format string contains %n — arbitrary write primitive
                # Even a hardcoded %n is a serious bug (intentional backdoor or mistake)
                score += 35

            elif fmt_analysis.get("has_unbounded"):
                # e.g.  scanf("%s", buf)  or  scanf("%[^\\n]", buf)




                # Also penalise relative to destination buffer size if known
                if dest.get("type") == "stack" and dest.get("estimated_size"):
                    score += 10   # stack destination makes it more exploitable

            elif fmt_analysis.get("all_bounded"):
                # All string specifiers have explicit widths — provably safe
                score -= 30

            elif fmt.get("is_constant") and not fmt_analysis:
                # Constant format but we couldn't read/parse it from the binary
                score -= 15

            elif fmt.get("is_global"):
                # Global string — possibly writable but probably constant
                score -= 10

        else:
            score -= 15   # no format info recovered

        # Stack destination matters regardless of format source
        if dest.get("type") == "stack":
            score += 5

        score = max(0, min(100, score))
        return _map_severity(score), round(score / 100.0, 2)

    # ── Standard scoring path ─────────────────────────────────────────────────
    score = rule.base_risk

    # Destination
    dest_type = dest.get("type", "unknown")
    if dest_type == "stack":
        score += 15
    elif dest_type == "global":
        score -= 5
    elif dest_type in ("argument", "unknown", "immediate", "stack_param_ref"):
        score -= 12

    # Source
    src_type = src.get("type", "unknown")
    if src_type in _CALLER_CONTROLLED:
        score += 8
    elif src_type in (ValType.IMMEDIATE, ValType.GLOBAL):
        score -= 12

    # Length / size
    if leng is not None:
        len_type = leng.get("type", "unknown")

        if leng.get("attacker_controlled"):
            score += 18
        elif len_type == ValType.IMMEDIATE:
            score -= 18   # constant size: base penalty (overridden below if overflow)
        elif len_type == ValType.GLOBAL:
            score -= 10
        elif len_type == ValType.UNKNOWN:
            score -= 3

        # ── Constant overflow detection ───────────────────────────────────────
        # If a hardcoded size is LARGER than the estimated destination buffer,
        # the overflow is statically provable — reverse the penalty and escalate.
        if (len_type == ValType.IMMEDIATE
                and dest_type == "stack"
                and dest.get("estimated_size") is not None):
            imm_size  = leng.get("imm_value") or 0
            est_dest  = dest.get("estimated_size") or 0
            if imm_size > 0 and est_dest > 0:
                if imm_size > est_dest:
                    # Provable overflow: reverse the -18 penalty and add bonus
                    score += 18    # undo the -18 applied above
                    ratio = imm_size / est_dest
                    if ratio >= 4:
                        score += 35   # e.g. 16384 into 2048 (log_bad_request)
                    elif ratio >= 2:
                        score += 20
                    else:
                        score += 10
                elif imm_size <= est_dest:
                    score -= 8    # copy fits: additional safety signal

    # Pass-through wrapper: lower confidence since the actual dangerous call site
    # is at the CALLERS of this function — the wrapper itself is just a relay.
    # We still flag it because knowing the wrapper exists helps analysts find callers.
    # But we lower confidence to distinguish it from a direct dangerous call.
    # Note: analysis.is_pass_through is checked here — import handled by callsite.py
    try:
        if analysis.is_pass_through:
            score -= 3   # relay: risk at caller but wrapper still HIGH if args dangerous
    except AttributeError:
        pass

    # Bounds check
    if bc.found:
        if bc.signed_risk:
            score -= 5    # signed comparison — bypassable with negative value
        else:
            score -= 22   # unsigned comparison — meaningful mitigation

    # Argument quality penalty
    # When no meaningful argument data was recovered (all UNKNOWN), the finding
    # provides no actionable context — typically STL/CRT internals or deeply
    # nested virtual dispatch chains where static analysis cannot trace the args.
    def _known(v):
        return v not in (ValType.UNKNOWN, "unknown", None)
    
    dest_known = _known(dest_type)
    src_known  = _known(src.get("type"))
    len_known  = leng is not None and _known(leng.get("type"))
    
    known_count = sum([dest_known, src_known, len_known])
    if known_count == 0:
        score -= 25   # all-unknown: no actionable information
    elif known_count == 1:
        score -= 10   # only one arg traced: weak evidence

    # Unbounded copy category
    if rule.category == CAT_UNBOUNDED_COPY:
        score += 5

    score = max(0, min(100, score))
    return _map_severity(score), round(score / 100.0, 2)


def _map_severity(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 42:
        return "MEDIUM"
    if score >= 18:
        return "LOW"
    return "INFO"


def apply_scoring(analyses: List[CallSiteAnalysis]) -> List[CallSiteAnalysis]:
    for a in analyses:
        a.severity, a.confidence = score_finding(a)
    return sorted(analyses, key=lambda x: x.confidence, reverse=True)
