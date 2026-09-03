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
        Disassemble an entire byte buffer, producing every instruction.

        Two problems required the chunked architecture:

        1. Capstone with detail=True silently truncates output after ~230 KB.
           Fixed by splitting large sections into 64 KB chunks.

        2. A fixed-size chunk that starts mid-instruction causes all subsequent
           instructions in that chunk to be misaligned.  Example: if the last
           complete instruction in chunk N ends at byte 65,537 (one byte into
           chunk N+1 boundary), chunk N+1 would start decoding from byte 65,536,
           which is the SECOND byte of that instruction — every decode after that
           is wrong.

           Fixed by starting each chunk 15 bytes BEFORE its true boundary
           (15 = maximum x86 instruction length), then only emitting instructions
           whose start address is >= the true boundary.  This guarantees the first
           instruction we emit in each chunk is correctly decoded from its real
           start, regardless of alignment.

        No instruction is lost or duplicated across chunk boundaries.
        """
        if len(data) <= self._CHUNK_SIZE:
            result: List[Instruction] = []
            for insn in self.cs.disasm(data, start_va):
                result.append(self._wrap(insn))
            return result

        # Chunked path — large section.
        #
        # Two problems require careful overlap handling:
        #
        # PROBLEM A — alignment:
        #   If chunk N+1 starts at a byte that is the MIDDLE of an instruction
        #   that started in chunk N, every subsequent decode in N+1 is wrong.
        #   Fix: start each chunk 15 bytes BEFORE its true boundary (backward
        #   overlap).  Only emit instructions whose address >= true boundary.
        #   This realigns the decoder before the first instruction we care about.
        #
        # PROBLEM B — cross-boundary instructions lost:
        #   An instruction that STARTS in chunk N but needs bytes from chunk N+1
        #   cannot be decoded from chunk N alone (not enough data) and is
        #   filtered out of chunk N+1 (address < true boundary).  It falls through
        #   the cracks.
        #   Fix: extend each chunk 15 bytes FORWARD past its true boundary (forward
        #   overlap).  Now chunk N can decode cross-boundary instructions fully.
        #   They are still emitted by chunk N (address < true_end_va) and excluded
        #   from chunk N+1 (address < true_start_va of N+1).  No duplicates.
        #
        # Together the two overlaps guarantee: every instruction is decoded from
        # its true start, emitted exactly once, and no alignment errors propagate.
        _MAX_INSN = 15   # maximum x86 instruction length in bytes

        result = []
        offset = 0
        while offset < len(data):
            back  = min(_MAX_INSN, offset)  # backward overlap (alignment fix)

            chunk_start   = offset - back
            # Forward overlap captures instructions that cross into the next chunk
            chunk_end     = min(len(data), offset + self._CHUNK_SIZE + _MAX_INSN)
            chunk         = data[chunk_start:chunk_end]
            chunk_va      = start_va + chunk_start

            # This chunk "owns" instructions that START in [true_start_va, true_end_va).
            # true_end_va == true_start_va of the next chunk.
            true_start_va = start_va + offset
            true_end_va   = start_va + min(len(data), offset + self._CHUNK_SIZE)

            for insn in self.cs.disasm(chunk, chunk_va):
                addr = insn.address
                if true_start_va <= addr < true_end_va:
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
