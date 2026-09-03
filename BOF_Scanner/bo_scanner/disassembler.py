"""
Capstone-based x86 (32-bit) disassembler wrapper.

Key design choice: each Instruction stores the raw capstone CsInsn object
(_cs_insn) so data-flow and import modules can access operand detail without
re-disassembling. The field is hidden from repr/print.
"""
from dataclasses import dataclass, field
from typing import Iterator, List, Optional

import capstone


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes
    # Raw capstone object — needed by dataflow/imports for operand detail
    _cs_insn: object = field(default=None, repr=False, compare=False)

    # ── Convenience predicates ───────────────────────────────────────────────
    @property
    def is_call(self) -> bool:
        return self.mnemonic == "call"

    @property
    def is_push(self) -> bool:
        return self.mnemonic == "push"

    @property
    def is_pop(self) -> bool:
        return self.mnemonic == "pop"

    @property
    def is_ret(self) -> bool:
        return self.mnemonic in ("ret", "retn")

    @property
    def is_jmp(self) -> bool:
        return self.mnemonic == "jmp"

    @property
    def is_jcc(self) -> bool:
        """True for any conditional jump."""
        m = self.mnemonic
        return m.startswith("j") and m != "jmp"

    @property
    def is_cmp_or_test(self) -> bool:
        return self.mnemonic in ("cmp", "test")

    @property
    def is_function_prologue(self) -> bool:
        """Heuristic: push ebp / mov ebp,esp sequence starts here."""
        return (
            self.mnemonic == "push"
            and self.op_str in ("ebp",)
        )

    @property
    def full_str(self) -> str:
        return f"0x{self.address:08X}  {self.mnemonic.upper():<8s} {self.op_str}"

    def __len__(self) -> int:
        return len(self.raw_bytes)


class Disassembler:
    """Thin wrapper around capstone for x86 32-bit Intel-syntax disassembly."""

    def __init__(self) -> None:
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs.detail = True
        self.cs.syntax = capstone.CS_OPT_SYNTAX_INTEL

    # Capstone with detail=True has an internal limit that causes it to stop
    # early on large (>~230 KB) buffers.  Chunked disassembly sidesteps this.
    _CHUNK_SIZE = 65536  # 64 KB per pass

    def disassemble(self, data: bytes, start_va: int) -> List[Instruction]:
        """
        Disassemble an entire byte buffer.

        Large buffers are processed in _CHUNK_SIZE chunks to work around a
        capstone detail-mode limitation that silently truncates output on
        inputs larger than ~230 KB.  Instructions at chunk boundaries may
        occasionally be lost, but these are typically in embedded data tables
        rather than executable function prologues.
        """
        if len(data) <= self._CHUNK_SIZE:
            result: List[Instruction] = []
            for insn in self.cs.disasm(data, start_va):
                result.append(self._wrap(insn))
            return result

        # Chunked path — large section
        result = []
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self._CHUNK_SIZE]
            chunk_va = start_va + offset
            for insn in self.cs.disasm(chunk, chunk_va):
                result.append(self._wrap(insn))
            offset += self._CHUNK_SIZE
        return result

    def disassemble_n(self, data: bytes, start_va: int, offset: int, count: int) -> List[Instruction]:
        """Disassemble at most 'count' instructions from data[offset:]."""
        result: List[Instruction] = []
        for insn in self.cs.disasm(data[offset:], start_va + offset):
            result.append(self._wrap(insn))
            if len(result) >= count:
                break
        return result

    @staticmethod
    def _wrap(insn) -> Instruction:
        return Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw_bytes=bytes(insn.bytes),
            _cs_insn=insn,
        )
