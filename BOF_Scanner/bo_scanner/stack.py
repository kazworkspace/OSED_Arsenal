"""
Stack frame analysis, buffer size estimation, and ESP-delta tracking.

EBP-frame functions:
    get_stack_frame_size() extracts the SUB ESP, N allocation.
    classify_destination() maps [EBP-N] → stack buffer descriptor.

Frameless functions (no EBP frame pointer):
    EspTracker does a forward pass to compute the ESP delta at each
    instruction.  classify_destination() uses this to convert [ESP+K]
    → approximate frame-local descriptor.

Size caveat (applies to both modes):
    `sub esp, 0x40` allocates 64 bytes for the WHOLE frame.
    We report an upper-bound estimate, not the intended size of one buffer.
"""
from typing import Dict, List, Optional

import capstone.x86 as x86

from .disassembler import Instruction
from .dataflow import ArgumentValue, ValType


# ── ESP delta tracker ────────────────────────────────────────────────────────

class EspTracker:
    """
    Forward-pass tracker for the ESP delta across a function's instruction list.

    At function entry, ESP is treated as offset 0 (reference point).
    Each instruction that modifies ESP is applied; the running delta is
    recorded before the modification (so delta_at(i) = ESP state ENTERING
    instruction i, which is the state available to that instruction's memory
    operands).

    Use case: frameless functions that access locals via [ESP+K].  Given the
    delta at the access point, the frame-relative position is delta+K.
    """

    def __init__(self, instructions: List[Instruction]) -> None:
        self._deltas: List[int] = []
        delta = 0
        for insn in instructions:
            self._deltas.append(delta)   # record BEFORE applying this insn
            delta += self._esp_effect(insn)

    def delta_at(self, idx: int) -> int:
        """
        Return the ESP delta (relative to function entry) AT instruction idx.
        Negative values mean ESP has decreased (grown downward).
        """
        if 0 <= idx < len(self._deltas):
            return self._deltas[idx]
        return 0

    def frame_size_from_deltas(self) -> Optional[int]:
        """
        Return the magnitude of the first large negative jump in the delta
        series (i.e., the frame allocation from SUB ESP, N).
        This is equivalent to get_stack_frame_size() but derived from the
        running delta rather than an opcode scan.
        """
        prev = 0
        for d in self._deltas:
            jump = d - prev
            if jump <= -4:          # significant allocation
                return -jump
            prev = d
        return None

    @staticmethod
    def _esp_effect(insn: Instruction) -> int:
        """Compute how much ESP changes after executing insn (signed, in bytes)."""
        m = insn.mnemonic
        cs = insn._cs_insn

        if m in ("push", "pushf", "pushfd", "pushfw"):
            return -4
        if m in ("pop", "popf", "popfd", "popfw"):
            return 4
        if m == "pushad":
            return -32    # 8 × 4 bytes
        if m == "popad":
            return 32
        if m == "pusha":
            return -16    # 8 × 2 bytes (16-bit form)
        if m == "popa":
            return 16

        # SUB ESP, imm  /  ADD ESP, imm
        if m in ("sub", "add") and cs is not None:
            try:
                ops = cs.operands
                if (len(ops) == 2
                        and ops[0].type == x86.X86_OP_REG
                        and cs.reg_name(ops[0].reg) in ("esp", "sp")
                        and ops[1].type == x86.X86_OP_IMM):
                    imm = ops[1].imm
                    return -imm if m == "sub" else imm
            except Exception:
                pass

        # ENTER size, level: pushes EBP (-4) then allocates size bytes
        if m == "enter" and cs is not None:
            try:
                ops = cs.operands
                if ops and ops[0].type == x86.X86_OP_IMM:
                    return -(4 + ops[0].imm)
            except Exception:
                pass

        # LEAVE: equivalent to MOV ESP,EBP + POP EBP.
        # We can't accurately recover without knowing the EBP value here;
        # return 0 and let the caller treat this as a boundary.
        return 0


# ── Frame-size detection ─────────────────────────────────────────────────────

def get_stack_frame_size(instructions: List[Instruction]) -> Optional[int]:
    """
    Detect local stack frame allocation from the function prologue.

    Scans the first 20 instructions for: SUB ESP, imm
    Returns the immediate (frame size) or None.
    """
    for insn in instructions[:20]:
        if insn.mnemonic != "sub":
            continue
        cs = insn._cs_insn
        if cs is None:
            continue
        try:
            ops = cs.operands
            if (len(ops) == 2
                    and ops[0].type == x86.X86_OP_REG
                    and cs.reg_name(ops[0].reg) == "esp"
                    and ops[1].type == x86.X86_OP_IMM):
                return ops[1].imm
        except Exception:
            continue
    return None


# ── Destination classification ────────────────────────────────────────────────

def classify_destination(
    arg_val: ArgumentValue,
    frame_size: Optional[int],
    esp_tracker: Optional[EspTracker] = None,
    at_idx: Optional[int] = None,
) -> Dict:
    """
    Classify a destination argument and return a buffer descriptor dict.

    Fields:
        type              "stack" | "global" | "argument" | "immediate" | "unknown"
        offset            EBP offset (int, negative for locals)
        estimated_size    int | None   (upper bound — frame may hold multiple locals)
        size_is_upper_bound  bool
        description       str
        confidence        float 0.0–1.0
    """
    result = {
        "type": "unknown",
        "offset": None,
        "estimated_size": None,
        "size_is_upper_bound": True,
        "description": str(arg_val),
        "confidence": 0.2,
    }

    # EBP-relative local (standard frame pointer model)
    if arg_val.type == ValType.STACK_LOCAL and arg_val.ebp_offset is not None:
        offset = arg_val.ebp_offset
        if offset < 0:
            est = abs(offset)
            if arg_val.is_address:
                # LEA [EBP-N] → this IS the address of the buffer; safe to classify.
                # If the EBP offset exceeds the detected static frame allocation,
                # the function uses dynamic stack expansion (alloca / __alloca_probe).
                uses_alloca = (
                    (frame_size is not None and est > frame_size + 16)
                    or (frame_size is None and est > 0x100)
                    # No detected static frame but large EBP offset → alloca()
                )
                if uses_alloca:
                    if frame_size is not None:
                        frame_note = f"detected static frame: 0x{frame_size:X} bytes; "
                    else:
                        frame_note = "no static frame detected; "
                    desc = (
                        f"[EBP-0x{est:X}] — dynamic stack buffer "
                        f"({frame_note}function uses alloca() for additional stack space)"
                    )
                else:
                    desc = (
                        f"[EBP-0x{est:X}] — local stack buffer "
                        f"(at most {est} bytes before EBP)"
                    )
                result.update({
                    "type": "stack",
                    "offset": offset,
                    "estimated_size": est,
                    "size_is_upper_bound": True,
                    "description": desc,
                    "uses_alloca": uses_alloca,
                    "confidence": 0.65 if uses_alloca else 0.75,
                })
            else:
                # MOV [EBP-N] → reading a POINTER stored at that stack slot.
                # The actual buffer is wherever the pointer points (likely heap).
                # Classifying it as a stack buffer would be wrong and misleading.
                result.update({
                    "type": "heap_pointer",
                    "offset": offset,
                    "estimated_size": None,
                    "description": (
                        f"*[EBP-0x{est:X}] — pointer stored in stack slot "
                        f"(points to heap or other buffer; actual size unknown)"
                    ),
                    "confidence": 0.30,
                })
        else:
            result.update({
                "type": "stack_param_ref",
                "description": arg_val.description,
                "confidence": 0.3,
            })

    # ESP-relative (frameless function or post-alloca access)
    elif arg_val.type == ValType.ESP_REL and arg_val.esp_offset is not None:
        k = arg_val.esp_offset

        # Try to compute actual frame position using EspTracker
        if esp_tracker is not None and at_idx is not None:
            delta = esp_tracker.delta_at(at_idx)   # negative after sub esp, N
            frame_pos = delta + k                   # relative to function entry ESP
            if frame_pos < 0:
                # Confirmed local — below function-entry ESP level
                est = abs(frame_pos)
                result.update({
                    "type": "stack",
                    "offset": frame_pos,            # virtual EBP equivalent
                    "estimated_size": est,
                    "size_is_upper_bound": True,
                    "description": (
                        f"[ESP+0x{k:X}] → frameless local "
                        f"(≈ [EBP-0x{est:X}], at most {est} bytes)"
                    ),
                    "confidence": 0.60 if arg_val.is_address else 0.45,
                })
                return result

        # Fallback: use frame_size heuristic if tracker unavailable
        if frame_size is not None and 0 <= k < frame_size:
            est = frame_size - k
            result.update({
                "type": "stack",
                "offset": -(frame_size - k),
                "estimated_size": est,
                "size_is_upper_bound": True,
                "description": (
                    f"[ESP+0x{k:X}] — likely frameless local "
                    f"(approx. {est} bytes, frame={frame_size:#x})"
                ),
                "confidence": 0.45 if arg_val.is_address else 0.30,
            })
        else:
            result.update({
                "type": "unknown",
                "description": arg_val.description
                    + " (ESP-relative; frame position uncertain)",
                "confidence": 0.20,
            })

    elif arg_val.type == ValType.FUNC_ARG:
        result.update({
            "type": "argument",
            "description": arg_val.description,
            "confidence": 0.35,
        })

    elif arg_val.type == ValType.FUNC_ARG_REGISTER:
        # Fastcall register argument — likely a pointer passed in ECX or EDX
        result.update({
            "type": "argument",
            "description": arg_val.description,
            "confidence": 0.30,
        })

    elif arg_val.type == ValType.GLOBAL:
        result.update({
            "type": "global",
            "description": arg_val.description,
            "confidence": 0.4,
        })

    elif arg_val.type == ValType.IMMEDIATE:
        result.update({
            "type": "immediate",
            "description": f"0x{arg_val.imm_value:X}",
            "confidence": 0.15,
        })

    return result
