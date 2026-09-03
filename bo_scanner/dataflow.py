"""
Backward data-flow analysis for x86 call-site argument recovery.

Two argument-passing styles are handled:

  PUSH-based (cdecl / stdcall):
      push arg2
      push arg1
      push arg0
      call target
    → scan backward from CALL collecting PUSH instructions.

  Framestore / MOV-based (GCC -O0, MSVC all levels):
      mov dword ptr [esp+8], arg2
      mov dword ptr [esp+4], arg1
      mov dword ptr [esp],   arg0
      call target
    → scan backward collecting MOV [ESP+N] slot assignments.

Both scans are run; results are merged slot-by-slot preferring PUSH (which
is direct evidence) over framestore (which needs a register/memory trace).

Fastcall:
  ECX and EDX arriving from the caller without a local definition are
  classified as ValType.FUNC_ARG_REGISTER.

ESP-tracker integration:
  An optional EspTracker resolves [ESP+K] addresses in frameless functions.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import capstone.x86 as x86

from .disassembler import Instruction


# ── Value type taxonomy ──────────────────────────────────────────────────────

class ValType:
    IMMEDIATE         = "immediate"
    STACK_LOCAL       = "stack_local"
    FUNC_ARG          = "func_arg"
    FUNC_ARG_REGISTER = "func_arg_register"   # ECX/EDX fastcall
    GLOBAL            = "global"
    ESP_REL           = "esp_rel"
    UNKNOWN           = "unknown"


@dataclass
class ArgumentValue:
    type: str = ValType.UNKNOWN
    imm_value: Optional[int] = None
    ebp_offset: Optional[int] = None
    arg_index: Optional[int] = None
    global_addr: Optional[int] = None
    esp_offset: Optional[int] = None
    is_address: bool = False
    description: str = ""

    def __str__(self) -> str:
        if self.description:
            return self.description
        if self.type == ValType.IMMEDIATE:
            return f"0x{self.imm_value:X}" if self.imm_value is not None else "0"
        if self.type == ValType.STACK_LOCAL:
            sign = "-" if (self.ebp_offset or 0) < 0 else "+"
            return f"[EBP{sign}0x{abs(self.ebp_offset or 0):X}]"
        if self.type == ValType.FUNC_ARG:
            return f"[EBP+0x{self.ebp_offset or 0:X}] (caller argument #{self.arg_index})"
        if self.type == ValType.FUNC_ARG_REGISTER:
            return self.description or f"register argument #{self.arg_index}"
        if self.type == ValType.GLOBAL:
            return f"[0x{self.global_addr or 0:08X}] (global/static)"
        return "unknown"


# ── Register normalisation ───────────────────────────────────────────────────

_REG_NORM: dict = {
    "al": "eax", "ah": "eax", "ax": "eax",
    "bl": "ebx", "bh": "ebx", "bx": "ebx",
    "cl": "ecx", "ch": "ecx", "cx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx",
    "si": "esi", "di": "edi",
    "sp": "esp", "bp": "ebp",
}

def _norm(reg: str) -> str:
    return _REG_NORM.get(reg, reg)


# ── BackwardDataFlow ─────────────────────────────────────────────────────────

class BackwardDataFlow:
    """
    Recover call arguments from two instruction patterns:

    1. PUSH-based (classic cdecl): scan backward for PUSH insns.
    2. Framestore (GCC/MSVC): scan backward for MOV [ESP+N], val insns.

    Results from both scans are merged per argument slot; PUSH-based takes
    priority when both produce a non-UNKNOWN value for the same slot.
    """

    MAX_LOOKBACK = 60   # wider window to catch framestore setups

    def __init__(
        self,
        instructions: List[Instruction],
        call_index: int,
        image_base: int,
        esp_tracker=None,
    ) -> None:
        self.instructions = instructions
        self.call_index = call_index
        self.image_base = image_base
        self._esp_tracker = esp_tracker

    # ── Public ───────────────────────────────────────────────────────────────

    def recover_arguments(self, num_args: int) -> List[ArgumentValue]:
        """
        Recover up to num_args arguments.  Tries both PUSH-based and
        MOV-based (framestore) scanning and merges the results.
        """
        push_args  = self._recover_push(num_args)
        frame_args = self._recover_framestore(num_args)
        merged     = self._merge(push_args, frame_args, num_args)

        # Pad with UNKNOWN if needed
        max_needed = max(num_args, 0)
        while len(merged) < max_needed:
            merged.append(ArgumentValue(
                type=ValType.UNKNOWN,
                description="not recovered (no push or framestore slot found)",
            ))
        return merged

    # ── PUSH-based recovery ───────────────────────────────────────────────────

    def _recover_push(self, num_args: int) -> List[ArgumentValue]:
        max_collect = num_args if num_args > 0 else 8
        scan_floor = max(0, self.call_index - self.MAX_LOOKBACK)
        push_indices: List[int] = []

        for i in range(self.call_index - 1, scan_floor - 1, -1):
            insn = self.instructions[i]
            if insn.is_ret or insn.is_call:
                break
            if insn.is_push:
                push_indices.append(i)
                if len(push_indices) >= max_collect:
                    break

        args: List[ArgumentValue] = []
        for push_idx in push_indices:
            args.append(self._resolve_push(push_idx, scan_floor))
        return args

    def _resolve_push(self, push_idx: int, scan_floor: int) -> ArgumentValue:
        insn = self.instructions[push_idx]
        cs = insn._cs_insn
        if cs is None:
            return _unknown("no capstone detail")
        try:
            ops = cs.operands
            if not ops:
                return _unknown("push with no operands")
            op = ops[0]
            if op.type == x86.X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                return ArgumentValue(
                    type=ValType.IMMEDIATE, imm_value=v,
                    description=f"0x{v:X} (immediate constant)",
                )
            elif op.type == x86.X86_OP_REG:
                reg = cs.reg_name(op.reg)
                return self._trace_register(reg, push_idx, scan_floor)
            elif op.type == x86.X86_OP_MEM:
                return _classify_mem(op, cs, is_lea=False,
                                     esp_tracker=self._esp_tracker, at_idx=push_idx)
        except Exception as e:
            return _unknown(f"exception: {e}")
        return _unknown()

    # ── Framestore (MOV [ESP+N]) recovery ─────────────────────────────────────

    def _recover_framestore(self, num_args: int) -> List[ArgumentValue]:
        """
        Scan backward for MOV [ESP+N], val patterns.
        The slot at offset 0 = arg0, +4 = arg1, +8 = arg2, etc.

        Key difference from PUSH scan: we do NOT stop at intermediate CALL
        instructions when collecting slots.  Memory at [ESP+N] persists
        across calls (unlike register values).  We DO stop at CALL when
        tracing the register/memory source of each slot value.
        """
        max_collect = num_args if num_args > 0 else 8
        scan_floor = max(0, self.call_index - self.MAX_LOOKBACK)

        # slot_offset → (insn_idx, capstone_insn, src_operand)
        # First encounter scanning backward = most recent assignment = correct
        slots: Dict[int, Tuple[int, object, object]] = {}

        for i in range(self.call_index - 1, scan_floor - 1, -1):
            insn = self.instructions[i]
            cs = insn._cs_insn
            if cs is None:
                continue
            if insn.is_ret:
                break
            # Do NOT break on is_call — [esp+N] memory persists across calls

            m = insn.mnemonic
            if m not in ("mov", "movzx", "movsx"):
                continue

            try:
                ops = cs.operands
                if len(ops) != 2:
                    continue
                dst, src = ops[0], ops[1]

                # Pattern: MOV [ESP + disp], val
                if dst.type != x86.X86_OP_MEM:
                    continue
                mem = dst.mem
                base = _norm(cs.reg_name(mem.base)) if mem.base != 0 else None
                if base not in ("esp", "sp"):
                    continue
                if mem.index != 0:
                    continue   # skip scaled-index modes

                slot = mem.disp
                if slot < 0:
                    continue   # negative offsets aren't outgoing args
                if slot not in slots:
                    slots[slot] = (i, cs, src)

            except Exception:
                continue

        # Build argument list from slot map
        args: List[ArgumentValue] = []
        for arg_idx in range(max_collect):
            slot = arg_idx * 4
            if slot not in slots:
                break   # stop at first missing slot
            insn_idx, cs, src_op = slots[slot]
            args.append(self._resolve_slot_src(src_op, cs, insn_idx, scan_floor))

        return args

    def _resolve_slot_src(
        self, src_op, cs, at_idx: int, scan_floor: int
    ) -> ArgumentValue:
        """Resolve the source operand of a MOV [ESP+N], src instruction."""
        try:
            if src_op.type == x86.X86_OP_IMM:
                v = src_op.imm & 0xFFFFFFFF
                return ArgumentValue(
                    type=ValType.IMMEDIATE, imm_value=v,
                    description=f"0x{v:X} (immediate constant)",
                )
            elif src_op.type == x86.X86_OP_REG:
                reg = cs.reg_name(src_op.reg)
                return self._trace_register(reg, at_idx, scan_floor)
            elif src_op.type == x86.X86_OP_MEM:
                return _classify_mem(src_op, cs, is_lea=False,
                                     esp_tracker=self._esp_tracker, at_idx=at_idx)
        except Exception as e:
            return _unknown(f"slot resolve: {e}")
        return _unknown()

    # ── Merge push + framestore results ───────────────────────────────────────

    @staticmethod
    def _merge(
        push_args: List[ArgumentValue],
        frame_args: List[ArgumentValue],
        num_args: int,
    ) -> List[ArgumentValue]:
        """
        For each argument slot, prefer the PUSH result when non-UNKNOWN;
        fall back to the framestore result; then UNKNOWN.
        """
        n = max(len(push_args), len(frame_args), max(num_args, 0))
        result = []
        for i in range(n):
            p = push_args[i]  if i < len(push_args)  else ArgumentValue(type=ValType.UNKNOWN)
            f = frame_args[i] if i < len(frame_args) else ArgumentValue(type=ValType.UNKNOWN)
            if p.type != ValType.UNKNOWN:
                result.append(p)
            elif f.type != ValType.UNKNOWN:
                result.append(f)
            else:
                result.append(p)   # both unknown — keep PUSH version
        return result

    # ── Register tracing ──────────────────────────────────────────────────────

    def _trace_register(
        self, reg: str, from_idx: int, scan_floor: int
    ) -> ArgumentValue:
        reg = _norm(reg)
        for i in range(from_idx - 1, scan_floor - 1, -1):
            insn = self.instructions[i]
            cs = insn._cs_insn
            if cs is None:
                continue
            if insn.is_ret or insn.is_call:
                break
            if not _writes_to(cs, reg):
                continue

            m = insn.mnemonic
            if m == "lea":
                return self._analyze_lea(cs, at_idx=i)
            elif m in ("mov", "movzx", "movsx"):
                return self._analyze_mov_src(cs, at_idx=i)
            elif m == "xor":
                ops = cs.operands
                if (len(ops) == 2
                        and ops[0].type == x86.X86_OP_REG
                        and ops[1].type == x86.X86_OP_REG
                        and _norm(cs.reg_name(ops[0].reg)) == reg
                        and _norm(cs.reg_name(ops[1].reg)) == reg):
                    return ArgumentValue(
                        type=ValType.IMMEDIATE, imm_value=0,
                        description="0 (zeroed via XOR self)",
                    )
                return _unknown(f"{reg} after XOR")
            elif m == "pop":
                return _unknown(f"{reg} from stack (popped)")
            elif m in ("add", "sub", "imul", "and", "or", "not", "neg",
                       "shl", "shr", "sar", "xchg"):
                return _unknown(f"{reg} after {m} (arithmetic/width-change)")
            else:
                return _unknown(f"{reg} after {m}")

        # ECX/EDX not defined locally → fastcall incoming register argument
        if reg in ("ecx", "edx"):
            reg_idx = 0 if reg == "ecx" else 1
            return ArgumentValue(
                type=ValType.FUNC_ARG_REGISTER,
                arg_index=reg_idx,
                description=(
                    f"{reg.upper()} — potential fastcall argument #{reg_idx} "
                    f"(no local definition found)"
                ),
            )
        return _unknown(f"{reg} (not found in lookback window)")

    # ── LEA / MOV source ─────────────────────────────────────────────────────

    def _analyze_lea(self, cs, at_idx: Optional[int] = None) -> ArgumentValue:
        ops = cs.operands
        if len(ops) < 2 or ops[1].type != x86.X86_OP_MEM:
            return _unknown("unexpected LEA form")
        return _classify_mem(ops[1], cs, is_lea=True,
                             esp_tracker=self._esp_tracker, at_idx=at_idx)

    def _analyze_mov_src(self, cs, at_idx: Optional[int] = None) -> ArgumentValue:
        ops = cs.operands
        if len(ops) < 2:
            return _unknown("unexpected MOV form")
        src = ops[1]
        if src.type == x86.X86_OP_IMM:
            v = src.imm & 0xFFFFFFFF
            return ArgumentValue(type=ValType.IMMEDIATE, imm_value=v,
                                 description=f"0x{v:X} (constant)")
        elif src.type == x86.X86_OP_MEM:
            return _classify_mem(src, cs, is_lea=False,
                                 esp_tracker=self._esp_tracker, at_idx=at_idx)
        elif src.type == x86.X86_OP_REG:
            return _unknown(f"from {cs.reg_name(src.reg)} (reg transfer, not traced)")
        return _unknown()


# ── Module-level helpers ──────────────────────────────────────────────────────

def _unknown(reason: str = "") -> ArgumentValue:
    desc = f"unknown ({reason})" if reason else "unknown"
    return ArgumentValue(type=ValType.UNKNOWN, description=desc)


def _writes_to(cs, reg32: str) -> bool:
    try:
        ops = cs.operands
        if ops and ops[0].type == x86.X86_OP_REG:
            if _norm(cs.reg_name(ops[0].reg)) == reg32:
                return True
        for r in cs.regs_write:
            if _norm(cs.reg_name(r)) == reg32:
                return True
    except Exception:
        pass
    return False


def _classify_mem(
    op, cs, is_lea: bool,
    esp_tracker=None, at_idx: Optional[int] = None,
) -> ArgumentValue:
    try:
        mem = op.mem
        base_reg   = _norm(cs.reg_name(mem.base))  if mem.base  != 0 else None
        index_reg  = _norm(cs.reg_name(mem.index)) if mem.index != 0 else None
        disp = mem.disp

        # ── EBP-relative ──────────────────────────────────────────────────────
        if base_reg == "ebp" and index_reg is None:
            if disp < 0:
                return ArgumentValue(
                    type=ValType.STACK_LOCAL, ebp_offset=disp, is_address=is_lea,
                    description=f"[EBP-0x{abs(disp):X}]" + (" (address-of)" if is_lea else ""),
                )
            elif disp >= 8:
                arg_idx = (disp - 8) // 4
                return ArgumentValue(
                    type=ValType.FUNC_ARG, ebp_offset=disp, arg_index=arg_idx,
                    is_address=is_lea,
                    description=f"[EBP+0x{disp:X}] (caller argument #{arg_idx})",
                )
            else:
                return _unknown(f"[EBP+0x{disp:X}] (frame metadata)")

        # ── ESP-relative (frameless) ───────────────────────────────────────────
        if base_reg in ("esp", "sp") and index_reg is None:
            if esp_tracker is not None and at_idx is not None:
                delta = esp_tracker.delta_at(at_idx)
                frame_pos = delta + disp
                if frame_pos < 0:
                    return ArgumentValue(
                        type=ValType.STACK_LOCAL,
                        ebp_offset=frame_pos,
                        esp_offset=disp,
                        is_address=is_lea,
                        description=(
                            f"[ESP+0x{disp:X}] → frameless local "
                            f"(≈ [EBP-0x{abs(frame_pos):X}])"
                            + (" (address-of)" if is_lea else "")
                        ),
                    )
            sign = "+" if disp >= 0 else "-"
            return ArgumentValue(
                type=ValType.ESP_REL, esp_offset=disp, is_address=is_lea,
                description=f"[ESP{sign}0x{abs(disp):X}] (stack-relative)",
            )

        # ── Absolute address ───────────────────────────────────────────────────
        if base_reg is None and index_reg is None and disp != 0:
            addr = disp & 0xFFFFFFFF
            return ArgumentValue(
                type=ValType.GLOBAL, global_addr=addr, is_address=is_lea,
                description=f"[0x{addr:08X}] (global/static)",
            )

    except Exception as e:
        return _unknown(f"mem classify error: {e}")

    return _unknown("complex memory operand")
