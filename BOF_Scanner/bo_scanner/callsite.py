"""
Call site analysis — orchestration layer.

New in this version:
  - format_string field: tracks the format-string argument for CAT_FORMAT_STRING rules
  - imm_value stored in length dict: enables constant-overflow scoring
  - Both PUSH and framestore argument recovery paths active
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .bounds import BoundsCheckResult, detect_bounds_check
from .dataflow import ArgumentValue, BackwardDataFlow, ValType
from .disassembler import Instruction
from .functions import Function
from .imports import ImportResolver
from .pe import PEContext
from .rules import APIRule, CAT_INDIRECT_UNRESOLVED, UNRESOLVED_INDIRECT_RULE
from .stack import EspTracker, classify_destination, get_stack_frame_size
from .format_parser import parse_format_string, analyze_format_danger
from .pe import read_cstring_at
import capstone.x86 as _x86

_CALLER_CONTROLLED = {ValType.FUNC_ARG, ValType.FUNC_ARG_REGISTER}


def _is_in_thunk_table(insns, idx, resolver) -> bool:
    """Return True if the JMP at insns[idx] is inside a consecutive IAT thunk table."""
    if idx == 0:
        return False
    prev = insns[idx - 1]
    if prev.mnemonic != "jmp":
        return False
    prev_cs = prev._cs_insn
    if prev_cs is None:
        return False
    try:
        for op in prev_cs.operands:
            if (op.type == _x86.X86_OP_MEM
                    and op.mem.base == 0 and op.mem.index == 0):
                addr = op.mem.disp & 0xFFFFFFFF
                if addr in resolver._iat_map:
                    return True
    except Exception:
        pass
    return False


@dataclass
class CallSiteAnalysis:
    function_name: str
    function_start: int
    call_address: int
    api_name: str
    rule: APIRule

    arguments: List[ArgumentValue] = field(default_factory=list)
    destination: Dict = field(default_factory=dict)
    source: Dict = field(default_factory=dict)
    length: Optional[Dict] = None
    format_string: Optional[Dict] = None   # NEW: format arg info for CAT_FORMAT_STRING

    bounds_check: BoundsCheckResult = field(
        default_factory=lambda: BoundsCheckResult(found=False)
    )
    frame_size: Optional[int] = None
    evidence: List[str] = field(default_factory=list)
    is_tail_call: bool = False
    # True when dest/src/len are ALL caller arguments — function is a relay.
    # The actual risk is at the call sites of this function, not here.
    is_pass_through: bool = False

    severity: str = "INFO"
    confidence: float = 0.0


def analyze_call_sites(
    functions: List[Function],
    resolver: ImportResolver,
    pe: PEContext,
    filter_api: Optional[str] = None,
    filter_func_va: Optional[int] = None,
) -> List[CallSiteAnalysis]:
    results: List[CallSiteAnalysis] = []

    for func in functions:
        if filter_func_va is not None and func.start_va != filter_func_va:
            continue
        insns = func.instructions
        if not insns:
            continue

        frame_size = get_stack_frame_size(insns)
        esp_tracker = EspTracker(insns)

        for idx, insn in enumerate(insns):
            m = insn.mnemonic
            api_name: Optional[str] = None
            rule: Optional[APIRule] = None
            is_tail_call = False
            is_indirect_unresolved = False

            if insn.is_call:
                api_name, rule = resolver.is_dangerous_call_ctx(insns, idx)
                if api_name is None:
                    # Check if the call resolves to a known but non-dangerous API
                    # (send, closesocket, WSAGetLastError via Pattern D).
                    # If so, skip silently — listing it as "unresolved" adds noise.
                    _resolved_safe = resolver.resolve_call_ctx(insns, idx)
                    if _resolved_safe is not None:
                        continue   # known non-dangerous API, skip
                    indirect_desc = resolver.classify_indirect_call(insns, idx)
                    if indirect_desc:
                        is_indirect_unresolved = True
                        api_name = indirect_desc
                        rule = UNRESOLVED_INDIRECT_RULE
            elif m == "jmp":
                api_name, rule = resolver.is_dangerous_jump(insn)
                if api_name:
                    if len(insns) <= 3:
                        continue
                    if _is_in_thunk_table(insns, idx, resolver):
                        continue
                    is_tail_call = True

            if api_name is None:
                continue
            if filter_api and api_name.lower() != filter_api.lower():
                continue

            # ── Unresolved indirect: minimal record ──────────────────────────
            if is_indirect_unresolved:
                ev_start = max(0, idx - 4)
                results.append(CallSiteAnalysis(
                    function_name=func.name, function_start=func.start_va,
                    call_address=insn.address, api_name=api_name, rule=rule,
                    destination={"type": "unknown", "description": "unresolved",
                                 "estimated_size": None, "confidence": 0.0},
                    source={"type": "unknown", "description": "unresolved"},
                    frame_size=frame_size,
                    evidence=[i.full_str for i in insns[ev_start:idx + 1]],
                    severity="INFO", confidence=0.05,
                ))
                continue

            # ── Full argument recovery ────────────────────────────────────────
            num_args = rule.num_args if rule.num_args > 0 else 8
            df = BackwardDataFlow(insns, idx, pe.image_base, esp_tracker=esp_tracker)
            args = df.recover_arguments(num_args)

            # Destination
            dest_info: Dict = {
                "type": "unknown", "description": "not recovered",
                "estimated_size": None, "confidence": 0.1,
            }
            if rule.dest_arg is not None and rule.dest_arg < len(args):
                dest_arg = args[rule.dest_arg]
                dest_info = classify_destination(
                    dest_arg, frame_size, esp_tracker=esp_tracker, at_idx=idx,
                )

            # Source
            src_info: Dict = {"type": "unknown", "description": "not recovered"}
            if rule.src_arg is not None and rule.src_arg < len(args):
                sv = args[rule.src_arg]
                src_info = {"type": sv.type, "description": str(sv)}

            # Length / size — include imm_value for constant overflow check
            len_info: Optional[Dict] = None
            if rule.size_arg is not None:
                if rule.size_arg < len(args):
                    lv = args[rule.size_arg]
                    len_info = {
                        "type": lv.type,
                        "description": str(lv),
                        "imm_value": lv.imm_value,   # NEW: for constant overflow scoring
                        "attacker_controlled": lv.type in _CALLER_CONTROLLED,
                    }
                else:
                    len_info = {
                        "type": "unknown", "description": "not recovered",
                        "imm_value": None,
                        "attacker_controlled": False,
                    }

            # Format string argument (CAT_FORMAT_STRING rules)
            fmt_info: Optional[Dict] = None
            if rule.format_arg is not None:
                if rule.format_arg < len(args):
                    fv = args[rule.format_arg]
                    fmt_info = {
                        "type": fv.type,
                        "description": str(fv),
                        "attacker_controlled": fv.type in _CALLER_CONTROLLED,
                        "is_constant": fv.type == ValType.IMMEDIATE,
                        "is_global": fv.type == ValType.GLOBAL,
                    }
                else:
                    fmt_info = {
                        "type": "unknown", "description": "not recovered",
                        "attacker_controlled": False,
                        "is_constant": False, "is_global": False,
                    }

            # ── Format string content analysis ───────────────────────────────
            # When the format arg is a compile-time constant address, read the
            # actual string from the binary and parse its specifiers.
            # This detects dangerous patterns like %s and %[^\n] without width.
            if fmt_info and fv.type == ValType.IMMEDIATE and fv.imm_value:
                fmt_literal = read_cstring_at(pe, fv.imm_value)
                if fmt_literal:
                    specs = parse_format_string(fmt_literal)
                    analysis = analyze_format_danger(specs)
                    fmt_info["format_literal"] = fmt_literal
                    fmt_info["format_analysis"] = analysis
                    # Upgrade is_constant semantics: a constant format with
                    # dangerous specifiers is actually dangerous, not safe.
                    if analysis["has_unbounded"] or analysis["has_write_primitive"]:
                        fmt_info["is_constant"] = False   # don't apply the safe-constant discount

            bounds = detect_bounds_check(insns, idx)

            ev_start = max(0, idx - 8)
            evidence = [i.full_str for i in insns[ev_start:idx + 1]]

            # Detect pass-through wrapper: all recoverable args come from caller
            _pt_types = {ValType.FUNC_ARG, ValType.FUNC_ARG_REGISTER}
            _dest_pt = (rule.dest_arg is None or
                        (rule.dest_arg < len(args) and args[rule.dest_arg].type in _pt_types))
            _src_pt  = (rule.src_arg is None or
                        (rule.src_arg < len(args) and args[rule.src_arg].type in _pt_types))
            _len_pt  = (rule.size_arg is None or
                        (rule.size_arg < len(args) and args[rule.size_arg].type in _pt_types))
            is_pass_through = _dest_pt and _src_pt and _len_pt

            results.append(CallSiteAnalysis(
                function_name=func.name, function_start=func.start_va,
                call_address=insn.address, api_name=api_name, rule=rule,
                arguments=args, destination=dest_info, source=src_info,
                length=len_info, format_string=fmt_info,
                bounds_check=bounds, frame_size=frame_size,
                evidence=evidence, is_tail_call=is_tail_call,
                is_pass_through=is_pass_through,
            ))

    return results
