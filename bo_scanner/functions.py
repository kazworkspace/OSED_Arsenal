"""
Function boundary detection for stripped x86 PE binaries.

Strategy (three passes, combined):
  1. Prologue scan — find `push ebp / mov ebp, esp` byte patterns.
  2. Call-target collection — any CALL to an in-binary address marks a
     function start.  This catches callbacks and optimizer-reordered code.
  3. Export table — exported functions are definite starts.

Known limitation: Optimized builds frequently omit `push ebp; mov ebp,esp`
(frame-pointer omission). Those functions will only appear if they are called
from within the binary. Functions that are *only* reached through pointers
stored in data will be missed entirely.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import capstone.x86 as x86

from .disassembler import Instruction


# Prologue byte patterns we look for
_PROLOGUE_BYTES = [
    bytes([0x55, 0x8B, 0xEC]),  # push ebp ; mov ebp, esp  (MSVC)
    bytes([0x55, 0x89, 0xE5]),  # push ebp ; mov ebp, esp  (GCC)
]


@dataclass
class Function:
    start_va: int
    end_va: int    # exclusive — first byte after this function
    instructions: List[Instruction] = field(default_factory=list, repr=False)

    export_name: Optional[str] = None   # populated from PE export table

    @property
    def name(self) -> str:
        return self.export_name or f"sub_{self.start_va:08X}"

    @property
    def size(self) -> int:
        return self.end_va - self.start_va

    def __repr__(self) -> str:
        return f"Function({self.name}, {self.size} bytes)"


def find_functions(
    code_sections: list,            # List[CodeSection]
    section_insns: Dict[int, List[Instruction]],  # sec.va → insn list
    image_base: int,
    export_vas: Optional[Set[int]] = None,
    export_names: Optional[Dict[int, str]] = None,  # va → symbol name
) -> List[Function]:
    """
    Detect function boundaries across all executable sections.
    Returns a deduplicated, sorted list of Function objects.
    """
    # ── Pass 1: collect all function start candidates ────────────────────────
    func_starts: Set[int] = set()

    # Exports are definite function starts
    if export_vas:
        func_starts.update(export_vas)

    # Call targets within the binary
    all_sections_range = [
        (sec.va, sec.va + sec.size) for sec in code_sections
    ]
    for insns in section_insns.values():
        for insn in insns:
            if insn.is_call:
                target = _direct_call_target(insn)
                if target is not None and _in_code(target, all_sections_range):
                    func_starts.add(target)

    # Prologue byte patterns in each section
    for sec in code_sections:
        for pat in _PROLOGUE_BYTES:
            offset = 0
            while True:
                idx = sec.data.find(pat, offset)
                if idx == -1:
                    break
                func_starts.add(sec.va + idx)
                offset = idx + 1

    # ── Pass 2: for each section, split into functions by starts ─────────────
    functions: List[Function] = []

    for sec in code_sections:
        insns = section_insns.get(sec.va, [])
        if not insns:
            continue

        # Starts that fall inside this section
        sec_starts = sorted(
            va for va in func_starts
            if sec.va <= va < sec.va + sec.size
        )

        # Always include section start so we don't drop leading code
        if not sec_starts or sec_starts[0] != sec.va:
            sec_starts = [sec.va] + sec_starts

        for i, start_va in enumerate(sec_starts):
            next_start = sec_starts[i + 1] if i + 1 < len(sec_starts) else sec.va + sec.size

            # Collect instructions in [start_va, next_start)
            func_insns = [
                ins for ins in insns
                if start_va <= ins.address < next_start
            ]
            if not func_insns:
                continue

            # Use the full range [start_va, next_start).
            # We deliberately do NOT stop at the first RET.
            # Large MSVC functions with /GS stack cookies, SEH, or early
            # error returns have multiple RET instructions; stopping at the
            # first one truncates the function body and misses dangerous API
            # calls that follow those early exits.
            ename = (export_names or {}).get(start_va)
            functions.append(Function(
                start_va=start_va,
                end_va=next_start,
                instructions=func_insns,
                export_name=ename,
            ))

    # Deduplicate by start address (keep the one with more instructions)
    seen: Dict[int, Function] = {}
    for f in functions:
        existing = seen.get(f.start_va)
        if existing is None or len(f.instructions) > len(existing.instructions):
            seen[f.start_va] = f

    return sorted(seen.values(), key=lambda f: f.start_va)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _direct_call_target(insn: Instruction) -> Optional[int]:
    """Extract the immediate target of a direct CALL instruction, or None."""
    cs = insn._cs_insn
    if cs is None:
        return None
    try:
        for op in cs.operands:
            if op.type == x86.X86_OP_IMM:
                return op.imm & 0xFFFFFFFF
    except Exception:
        pass
    return None


def _in_code(va: int, ranges: List) -> bool:
    return any(lo <= va < hi for lo, hi in ranges)
