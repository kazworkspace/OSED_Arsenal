"""
Output formatting.

New in this version:
  - Format string section for CAT_FORMAT_STRING findings
  - Constant overflow annotation when imm_size > est_dest
  - Signed bounds-check warning
  - Tail call marker
"""
import json
from typing import Dict, List

from .callsite import CallSiteAnalysis
from .dataflow import ValType
from .rules import CAT_INDIRECT_UNRESOLVED, CAT_FORMAT_STRING

_SEP = "=" * 64

_FINDING_LABELS = {
    "CRITICAL": "Potential Buffer Overflow",
    "HIGH":     "Likely Unsafe Memory Copy / Injection",
    "MEDIUM":   "Suspicious API Usage",
    "LOW":      "Suspicious API Usage (low confidence)",
    "INFO":     "Insufficient Bounds Evidence",
}


def format_text_report(
    findings: List[CallSiteAnalysis],
    binary_name: str,
    architecture: str = "x86",
    min_confidence: float = 0.0,
) -> str:
    dangerous = [
        f for f in findings
        if f.rule.category != CAT_INDIRECT_UNRESOLVED
        and f.confidence >= min_confidence
    ]
    indirect = [
        f for f in findings
        if f.rule.category == CAT_INDIRECT_UNRESOLVED
    ]

    lines = [
        _SEP,
        "  bo_scanner — Buffer Overflow / Format String Static Analysis",
        _SEP,
        f"  Binary       : {binary_name}",
        f"  Architecture : {architecture}",
        f"  Findings     : {len(dangerous)}",
        f"  Indirect (unresolved) : {len(indirect)}",
        _SEP,
        "",
        "DISCLAIMER: All findings are POTENTIAL issues from heuristic static analysis.",
        "Static analysis cannot confirm exploitability.",
        "Manual review of each call site is required before drawing conclusions.",
        "",
    ]

    if not dangerous:
        lines.append("No dangerous API findings at or above the confidence threshold.")
    else:
        for i, f in enumerate(dangerous, 1):
            sev   = f.severity
            label = _FINDING_LABELS.get(sev, "Suspicious API Usage")
            tail  = " [tail call via JMP]" if f.is_tail_call else ""
            is_fmt = f.rule.category == CAT_FORMAT_STRING

            lines += [
                _SEP,
                f"  [{sev}] #{i} — {label}{tail}",
                _SEP,
                f"  API          : {f.api_name}",
                f"  Category     : {f.rule.category}",
                f"  Call site    : 0x{f.call_address:08X}",
                f"  Function     : {f.function_name}  (starts 0x{f.function_start:08X})",
                f"  Confidence   : {f.confidence:.0%}",
                "",
            ]
            if f.is_pass_through:
                lines += [
                    "  NOTE: Pass-through wrapper — all arguments forwarded from caller.",
                    "        The actual risk depends on what the CALLERS of this function",
                    "        pass as arguments. Trace callers to assess exploitability.",
                    "",
                ]

            # Destination
            d = f.destination
            lines.append("  Destination  :")
            lines.append(f"    {d.get('description', 'not recovered')}")
            if d.get("estimated_size"):
                bound = ("upper bound — frame may hold multiple locals"
                         if d.get("size_is_upper_bound") else "exact")
                lines.append(
                    f"    estimated size: {d['estimated_size']} bytes ({bound})"
                )
            if d.get("uses_alloca"):
                lines.append(
                    "    NOTE: alloca() detected — actual stack frame is larger "
                    "than the static SUB ESP allocation"
                )
            if d.get("type") == "heap_pointer":
                lines.append(
                    "    NOTE: destination is a heap pointer — "
                    "actual buffer size requires runtime analysis"
                )
            lines.append("")

            # Format string (CAT_FORMAT_STRING)
            if is_fmt and f.format_string is not None:
                fmt = f.format_string
                lines.append("  Format arg   :")
                lines.append(f"    {fmt.get('description', 'not recovered')}")
                if fmt.get("attacker_controlled"):
                    lines.append(
                        "    *** FORMAT STRING IS POTENTIALLY ATTACKER-CONTROLLED ***"
                    )
                    lines.append(
                        "    Risk: %n enables arbitrary write; %x/%s can leak stack/heap memory"
                    )
                elif fmt.get("is_constant"):
                    lines.append("    (constant format string — low format-string risk)")
                lines.append("")
            elif not is_fmt:
                # Source
                lines.append("  Source       :")
                lines.append(f"    {f.source.get('description', 'not recovered')}")
                lines.append("")

            # Length
            if f.length is not None:
                leng = f.length
                lines.append("  Length       :")
                lines.append(f"    {leng.get('description', 'N/A')}")
                if leng.get("attacker_controlled"):
                    lines.append("    *** Potentially attacker-controlled ***")
                # Constant overflow annotation
                imm_size = leng.get("imm_value") or 0
                est_dest = d.get("estimated_size") or 0
                if (leng.get("type") == ValType.IMMEDIATE
                        and imm_size > 0 and est_dest > 0
                        and imm_size > est_dest):
                    ratio = imm_size / est_dest
                    lines.append(
                        f"    *** CONSTANT OVERFLOW: copy size 0x{imm_size:X} ({imm_size}) "
                        f"> destination estimate 0x{est_dest:X} ({est_dest}) "
                        f"({ratio:.1f}× overrun) — STATICALLY PROVABLE ***"
                    )
                lines.append("")

            # Bounds check
            lines.append("  Bounds check :")
            bc = f.bounds_check
            if bc.found:
                lines.append(
                    f"    DETECTED ({bc.jcc_type or 'unknown'} comparison)"
                )
                if bc.signed_risk:
                    lines.append(
                        "    *** SIGNED COMPARISON RISK: negative size bypasses this check ***"
                    )
                for ev in bc.evidence:
                    lines.append(f"      {ev}")
                lines.append(
                    "    NOTE: check may or may not cover the relevant argument"
                )
            else:
                lines.append("    NOT DETECTED in lookback window")
            lines.append("")

            if f.frame_size is not None:
                lines.append(
                    f"  Stack frame  : 0x{f.frame_size:X} ({f.frame_size}) bytes total"
                )
                lines.append("")

            lines.append("  Evidence     :")
            for ev_line in f.evidence:
                lines.append(f"    {ev_line}")
            lines.append("")
            lines.append(f"  Reason       : {f.rule.description}")
            lines.append("")

    if indirect:
        lines += [
            _SEP,
            "  UNRESOLVED INDIRECT CALLS",
            "  (target could not be identified — may or may not be dangerous)",
            _SEP, "",
        ]
        for f in indirect:
            lines.append(
                f"  0x{f.call_address:08X}  in {f.function_name} : {f.api_name}"
            )
            for ev in f.evidence:
                lines.append(f"      {ev}")
            lines.append("")

    lines.append(_SEP)
    return "\n".join(lines)


def format_json_report(
    findings: List[CallSiteAnalysis],
    binary_name: str,
    architecture: str = "x86",
    min_confidence: float = 0.0,
) -> Dict:
    dangerous = [
        f for f in findings
        if f.rule.category != CAT_INDIRECT_UNRESOLVED
        and f.confidence >= min_confidence
    ]
    indirect = [
        f for f in findings
        if f.rule.category == CAT_INDIRECT_UNRESOLVED
    ]
    return {
        "binary": binary_name,
        "architecture": architecture,
        "tool": "bo_scanner",
        "disclaimer": (
            "All findings are heuristic triage results. "
            "Static analysis cannot confirm exploitability. "
            "Manual review is required."
        ),
        "total_findings": len(dangerous),
        "findings": [_finding_to_dict(f) for f in dangerous],
        "unresolved_indirect_calls": [
            {
                "address": f"0x{f.call_address:08X}",
                "function": f.function_name,
                "description": f.api_name,
                "evidence": f.evidence,
            }
            for f in indirect
        ],
    }


def _finding_to_dict(f: CallSiteAnalysis) -> Dict:
    d = f.destination
    bc = f.bounds_check
    leng = f.length or {}
    imm_size = leng.get("imm_value") or 0
    est_dest = d.get("estimated_size") or 0
    constant_overflow = (
        leng.get("type") == ValType.IMMEDIATE
        and imm_size > 0 and est_dest > 0
        and imm_size > est_dest
    )
    return {
        "severity": f.severity,
        "label": _FINDING_LABELS.get(f.severity, "Suspicious API Usage"),
        "api": f.api_name,
        "category": f.rule.category,
        "address": f"0x{f.call_address:08X}",
        "function": f.function_name,
        "function_start": f"0x{f.function_start:08X}",
        "confidence": f.confidence,
        "is_tail_call": f.is_tail_call,
        "is_pass_through_wrapper": f.is_pass_through,
        "destination": {
            "type": d.get("type", "unknown"),
            "description": d.get("description", ""),
            "estimated_size": d.get("estimated_size"),
            "size_is_upper_bound": d.get("size_is_upper_bound", True),
            "offset": d.get("offset"),
        },
        "source": {
            "type": f.source.get("type", "unknown"),
            "description": f.source.get("description", ""),
        },
        "length": (
            {
                "type": leng.get("type", "unknown"),
                "description": leng.get("description", ""),
                "imm_value": leng.get("imm_value"),
                "attacker_controlled": leng.get("attacker_controlled", False),
                "constant_overflow": constant_overflow,
                "overflow_ratio": round(imm_size / est_dest, 2) if constant_overflow else None,
            }
            if f.length is not None else None
        ),
        "format_string": f.format_string,
        "bounds_check": {
            "detected": bc.found,
            "comparison_type": bc.jcc_type,
            "signed_integer_bypass_risk": bc.signed_risk,
            "description": bc.description,
            "evidence": bc.evidence,
        },
        "frame_size": f.frame_size,
        "evidence": f.evidence,
        "rule_description": f.rule.description,
    }
