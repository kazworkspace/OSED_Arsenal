"""
Import resolution and thunk detection.

Patterns handled:

  A — direct IAT call:    CALL DWORD PTR [iat_va]     (FF 15)
  B — thunk call:         CALL thunk → JMP [iat_va]   (E8 → FF 25)
  C — JMP tail call:      JMP DWORD PTR [iat_va]      (FF 25)
  D — register via IAT:   MOV reg, [iat_va]; CALL reg (common in C++ / MSVC builds)

Pattern D is the reason recv / socket calls from C++ code built with
MinGW show up as "unresolved indirect" — the compiler loads the IAT slot
into a register and then calls via the register rather than using FF 15.
We resolve it by doing a short backward register trace from the CALL.
"""
from typing import Dict, List, Optional, Tuple

import capstone.x86 as x86

from .disassembler import Disassembler, Instruction
from .pe import PEContext
from .rules import APIRule, get_all_dangerous_names, get_rule

# ── Register normalisation (local copy to avoid circular import) ──────────────
_REG_NORM_LOCAL: dict = {
    "al": "eax", "ah": "eax", "ax": "eax",
    "bl": "ebx", "bh": "ebx", "bx": "ebx",
    "cl": "ecx", "ch": "ecx", "cx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx",
    "si": "esi", "di": "edi",
    "sp": "esp", "bp": "ebp",
}

def _norm(reg: str) -> str:
    return _REG_NORM_LOCAL.get(reg, reg)


class ImportResolver:
    """
    Resolves CALL and JMP instructions to imported API names.
    Built once per binary; used for every candidate instruction.
    """

    _BACKTRACK_LIMIT = 20   # wider window for callee-saved register traces

    # Registers that a CALL may freely clobber (x86 cdecl/stdcall volatile set).
    # For callee-saved registers (EBX, ESI, EDI, EBP), a CALL does not clobber
    # them, so we can safely continue the backward trace past an intermediate call.
    _VOLATILE_REGS = frozenset({"eax", "ecx", "edx"})

    def __init__(self, pe: PEContext, disasm: Disassembler) -> None:
        self._pe = pe
        self._disasm = disasm
        self._iat_map: Dict[int, str] = {
            ie.iat_va: ie.name for ie in pe.imports
        }
        self._thunk_map: Dict[int, str] = {}
        self._scan_thunks()

    # ── Single-instruction resolution (no context) ────────────────────────────

    def resolve_call(self, insn: Instruction) -> Optional[str]:
        """Resolve a CALL via Pattern A or B (no backward trace)."""
        return self._resolve_by_operand(insn)

    def is_dangerous_call(self, insn: Instruction) -> Tuple[Optional[str], Optional[APIRule]]:
        """(api_name, rule) for Pattern A/B CALL, else (None, None)."""
        name = self.resolve_call(insn)
        if name is None:
            return None, None
        rule = get_rule(name)
        return (name, rule) if rule else (None, None)

    # ── Context-aware resolution (with instruction list) ──────────────────────

    def resolve_call_ctx(
        self, insns: List[Instruction], idx: int
    ) -> Optional[str]:
        """
        Resolve a CALL to an API name using the surrounding instructions.

        Tries Pattern A/B first, then Pattern D (MOV reg, [iat_va]; CALL reg).
        """
        insn = insns[idx]
        # Patterns A / B
        name = self._resolve_by_operand(insn)
        if name:
            return name
        # Pattern D: CALL via register loaded from IAT
        return self._resolve_register_iat(insns, idx)

    def is_dangerous_call_ctx(
        self, insns: List[Instruction], idx: int
    ) -> Tuple[Optional[str], Optional[APIRule]]:
        """(api_name, rule) using full context; covers Pattern D."""
        name = self.resolve_call_ctx(insns, idx)
        if name is None:
            return None, None
        rule = get_rule(name)
        return (name, rule) if rule else (None, None)

    # ── Dangerous JMP resolution (tail calls) ─────────────────────────────────

    def is_dangerous_jump(
        self, insn: Instruction
    ) -> Tuple[Optional[str], Optional[APIRule]]:
        """Check whether a JMP is a tail call to a dangerous API."""
        if insn.mnemonic != "jmp":
            return None, None
        name = self._resolve_by_operand(insn)
        if name is None:
            return None, None
        rule = get_rule(name)
        return (name, rule) if rule else (None, None)

    # ── Indirect call classification ──────────────────────────────────────────

    def classify_indirect_call(
        self, insns: List[Instruction], idx: int
    ) -> Optional[str]:
        """
        If this CALL cannot be resolved to a known API, return a description
        of the indirect call form.  Returns None if the call resolved (so
        callers should call resolve_call_ctx first and only fall through here
        if it returned None).
        """
        insn = insns[idx]
        if not insn.is_call:
            return None

        cs = insn._cs_insn
        if cs is None:
            return None
        try:
            for op in cs.operands:
                if op.type == x86.X86_OP_REG:
                    reg = cs.reg_name(op.reg)
                    return f"call {reg} (register indirect — target unresolved)"
                elif op.type == x86.X86_OP_MEM:
                    mem = op.mem
                    base = cs.reg_name(mem.base) if mem.base != 0 else None
                    index = cs.reg_name(mem.index) if mem.index != 0 else None
                    disp = mem.disp
                    if base is None and index is None:
                        return (
                            f"call dword ptr [0x{disp & 0xFFFFFFFF:08X}] "
                            f"(memory indirect — not in IAT)"
                        )
                    elif base:
                        parts = base
                        if index:
                            parts += f"+{index}"
                        if disp:
                            parts += f"{'+' if disp >= 0 else ''}{disp:#x}"
                        return f"call [{parts}] (register-based indirect — target unresolved)"
        except Exception:
            pass
        return None

    @property
    def thunk_count(self) -> int:
        return len(self._thunk_map)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _resolve_by_operand(self, insn: Instruction) -> Optional[str]:
        """Pattern A (CALL/JMP [iat_va]) and Pattern B (CALL/JMP thunk)."""
        cs = insn._cs_insn
        if cs is None:
            return None
        try:
            for op in cs.operands:
                if op.type == x86.X86_OP_MEM:
                    if op.mem.base == 0 and op.mem.index == 0:
                        addr = op.mem.disp & 0xFFFFFFFF
                        if addr in self._iat_map:
                            return self._iat_map[addr]
                elif op.type == x86.X86_OP_IMM:
                    target = op.imm & 0xFFFFFFFF
                    if target in self._thunk_map:
                        return self._thunk_map[target]
        except Exception:
            pass
        return None

    def _resolve_register_iat(
        self, insns: List[Instruction], call_idx: int
    ) -> Optional[str]:
        """
        Pattern D: scan backward from a CALL-via-register to find
        MOV reg, [iat_va] that loaded the function pointer.

        Handles the common pattern:
            MOV EAX, DWORD PTR [iat_slot]   ; load API function pointer
            CALL EAX                         ; call it
        """
        insn = insns[call_idx]
        cs = insn._cs_insn
        if cs is None:
            return None

        # Identify the register being called
        call_reg = None
        try:
            for op in cs.operands:
                if op.type == x86.X86_OP_REG:
                    call_reg = _norm(cs.reg_name(op.reg))
                    break
        except Exception:
            return None

        if call_reg is None:
            return None

        # Scan backward for MOV call_reg, [iat_va]
        floor = max(0, call_idx - self._BACKTRACK_LIMIT)
        for i in range(call_idx - 1, floor - 1, -1):
            prev = insns[i]
            prev_cs = prev._cs_insn
            if prev_cs is None:
                continue
            # Stop at instructions that clobber the register
            if prev.is_ret:
                break
            if prev.is_call:
                # Only volatile registers (EAX/ECX/EDX) are clobbered by a call.
                # Callee-saved registers (EBX/ESI/EDI/EBP) are preserved.
                if call_reg in self._VOLATILE_REGS:
                    break
                # Otherwise: continue scanning past this call.
                continue

            if prev.mnemonic not in ("mov", "movzx", "movsx"):
                # Check if this instruction writes to our register
                # (conservative: any write = stop)
                try:
                    ops = prev_cs.operands
                    if ops and ops[0].type == x86.X86_OP_REG:
                        if _norm(prev_cs.reg_name(ops[0].reg)) == call_reg:
                            break   # register clobbered by something other than MOV
                    for r in prev_cs.regs_write:
                        if _norm(prev_cs.reg_name(r)) == call_reg:
                            break
                except Exception:
                    pass
                continue

            try:
                ops = prev_cs.operands
                if len(ops) != 2:
                    continue
                dst, src = ops[0], ops[1]

                # Check: MOV call_reg, [iat_va]
                if (dst.type == x86.X86_OP_REG
                        and _norm(prev_cs.reg_name(dst.reg)) == call_reg
                        and src.type == x86.X86_OP_MEM
                        and src.mem.base == 0
                        and src.mem.index == 0):
                    addr = src.mem.disp & 0xFFFFFFFF
                    if addr in self._iat_map:
                        return self._iat_map[addr]
                    # Not in IAT — this MOV sets the register to something else,
                    # so it would be the last definition; stop looking.
                    break

            except Exception:
                continue

        return None

    def _scan_thunks(self) -> None:
        """Map thunk_va → api_name for JMP [iat_va] stubs."""
        for sec in self._pe.code_sections:
            insns = self._disasm.disassemble(sec.data, sec.va)
            for insn in insns:
                if insn.mnemonic != "jmp":
                    continue
                cs = insn._cs_insn
                if cs is None:
                    continue
                try:
                    for op in cs.operands:
                        if op.type == x86.X86_OP_MEM:
                            if op.mem.base == 0 and op.mem.index == 0:
                                addr = op.mem.disp & 0xFFFFFFFF
                                if addr in self._iat_map:
                                    self._thunk_map[insn.address] = self._iat_map[addr]
                except Exception:
                    continue
