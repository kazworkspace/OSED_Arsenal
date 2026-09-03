"""
Tests for chunk-boundary correctness in Disassembler.disassemble().

LESSON LEARNED: main.exe (quote_db compiled with MinGW on Windows) has a
3-byte instruction at VA 0x00410FFF that crosses the 64 KB chunk boundary at
VA 0x00411000.  The previous fixed-size chunking started Chunk 1 at byte 0x4E
(the 2nd byte of that instruction), misaligning every subsequent instruction
in Chunk 1.  Result: 49 thunks + memcpy calls became invisible; the CRITICAL
finding was never produced.

Fix: each chunk starts 15 bytes before its true boundary (15 = max x86 insn
length), then only emits instructions starting at or after the true boundary.

These tests exercise every aspect of the fix:
  1. Cross-boundary instruction is found with correct address
  2. Instruction immediately after a cross-boundary one is also found
  3. No instruction appears twice (no duplicates at boundary)
  4. Thunks that live just past a cross-boundary instruction are detected
  5. Regression: real binary (main.exe) yields the CRITICAL memcpy finding
"""
import os
import struct
import pytest
import capstone

from bo_scanner.disassembler import Disassembler


# ── helpers ──────────────────────────────────────────────────────────────────

CHUNK = Disassembler._CHUNK_SIZE   # 65536
SEC_VA = 0x00401000


def _make_section(parts):
    """Concatenate byte fragments into one section bytes object."""
    return b"".join(parts)


def _scan(data, va=SEC_VA):
    d = Disassembler()
    insns = d.disassemble(data, va)
    return {i.address: i for i in insns}


# ── Test 1: cross-boundary instruction is found ───────────────────────────────

class TestCrossBoundaryInstruction:
    """
    Layout:
        [0 .. CHUNK-3)   NOP sled
        [CHUNK-2]        first byte  ─┐
        [CHUNK-1]        second byte  ├─ MOV [ESI+0x10], ECX  (89 4E 10, 3 bytes)
        [CHUNK-0]        third byte  ─┘
        [CHUNK+1 ..]     NOP sled

    The instruction STARTS at offset CHUNK-2 (VA = SEC_VA + CHUNK - 2).
    Previous (broken) chunking started Chunk 1 at byte CHUNK, decoding
    0x10 (the third byte of MOV) as a standalone instruction → misaligned.
    """

    # 89 4E 10 = MOV DWORD PTR [ESI + 0x10], ECX  (3 bytes)
    CROSS_INSN = bytes([0x89, 0x4E, 0x10])

    def _build(self):
        nops_before = bytes([0x90]) * (CHUNK - 2)
        nops_after  = bytes([0x90]) * 32
        return _make_section([nops_before, self.CROSS_INSN, nops_after])

    def test_cross_boundary_insn_found(self):
        addr_map = _scan(self._build())
        target = SEC_VA + CHUNK - 2
        assert target in addr_map, (
            f"3-byte instruction crossing chunk boundary not found at {target:#010x}"
        )

    def test_cross_boundary_insn_length_is_3(self):
        addr_map = _scan(self._build())
        target = SEC_VA + CHUNK - 2
        assert target in addr_map
        assert len(addr_map[target].raw_bytes) == 3

    def test_instruction_after_boundary_found(self):
        """The NOP immediately after the 3-byte instruction must also appear."""
        addr_map = _scan(self._build())
        cross_end = SEC_VA + CHUNK - 2 + 3   # = SEC_VA + CHUNK + 1
        assert cross_end in addr_map, (
            f"Instruction after cross-boundary insn not found at {cross_end:#010x}"
        )

    def test_no_duplicates(self):
        d = Disassembler()
        insns = d.disassemble(self._build(), SEC_VA)
        addrs = [i.address for i in insns]
        assert len(addrs) == len(set(addrs)), (
            "Duplicate instructions found at or near chunk boundary"
        )

    def test_instruction_count_matches_bytes(self):
        """NOP sled + 3-byte insn + NOP sled → total insns = (CHUNK-2) + 1 + 32"""
        d = Disassembler()
        data = self._build()
        insns = d.disassemble(data, SEC_VA)
        expected = (CHUNK - 2) + 1 + 32   # nops + 3-byte + nops
        assert len(insns) == expected, f"Expected {expected}, got {len(insns)}"


# ── Test 2: instruction exactly at boundary ───────────────────────────────────

class TestInstructionAtBoundary:
    """
    Instruction starts EXACTLY at the chunk boundary (offset = CHUNK).
    This is the common case; the overlap should not break it.
    """

    def test_single_byte_at_boundary(self):
        """NOP at exactly offset CHUNK must be found."""
        data = bytes([0x90]) * (CHUNK + 10)
        addr_map = _scan(data)
        target = SEC_VA + CHUNK
        assert target in addr_map

    def test_three_byte_starts_at_boundary(self):
        """3-byte instruction starting exactly at the chunk boundary."""
        INSN = bytes([0x89, 0x4E, 0x10])
        data = bytes([0x90]) * CHUNK + INSN + bytes([0x90]) * 10
        addr_map = _scan(data)
        target = SEC_VA + CHUNK
        assert target in addr_map, (
            f"Instruction starting exactly at boundary not found at {target:#010x}"
        )
        assert len(addr_map[target].raw_bytes) == 3


# ── Test 3: multiple chunk boundaries ─────────────────────────────────────────

class TestMultipleChunks:
    """Sections spanning 3+ chunks; cross-boundary instruction in each gap."""

    CROSS_INSN = bytes([0x89, 0x4E, 0x10])   # 3 bytes

    def _build_3chunk(self):
        # Instruction crosses first boundary (CHUNK-2 .. CHUNK+1)
        part1 = bytes([0x90]) * (CHUNK - 2) + self.CROSS_INSN
        # Instruction crosses second boundary (2*CHUNK-2 .. 2*CHUNK+1)
        part2 = bytes([0x90]) * (CHUNK - 3) + self.CROSS_INSN
        # Rest
        part3 = bytes([0x90]) * 20
        return part1 + part2 + part3

    def test_both_cross_boundary_instructions_found(self):
        data = self._build_3chunk()
        addr_map = _scan(data)
        t1 = SEC_VA + CHUNK - 2
        t2 = SEC_VA + 2 * CHUNK - 2
        assert t1 in addr_map, f"First cross-boundary insn at {t1:#x} missing"
        assert t2 in addr_map, f"Second cross-boundary insn at {t2:#x} missing"

    def test_no_duplicates_multi_chunk(self):
        d = Disassembler()
        insns = d.disassemble(self._build_3chunk(), SEC_VA)
        addrs = [i.address for i in insns]
        assert len(addrs) == len(set(addrs))


# ── Test 4: thunk detection across chunk boundary ─────────────────────────────

class TestThunkDetectionAcrossBoundary:
    """
    If a 3-byte instruction crosses the chunk boundary and the thunk JMP
    follows immediately after, the thunk MUST be found by the thunk scanner.

    This is the exact failure seen in main.exe:
        0x00410FFF: MOV [ESI+0x10], ECX  (3 bytes, crosses 0x411000)
        ...
        0x00412F98: JMP [memcpy_iat]      (thunk — was invisible)
    """

    # JMP DWORD PTR [0x44B264]  (FF 25 64 B2 44 00)
    JMP_MEMCPY = bytes([0xFF, 0x25, 0x64, 0xB2, 0x44, 0x00])
    MEMCPY_IAT = 0x0044B264

    def _build(self, jmp_offset_from_boundary):
        """
        cross_insn at CHUNK-2, JMP at CHUNK + jmp_offset_from_boundary.
        """
        CROSS = bytes([0x89, 0x4E, 0x10])   # 3 bytes, starts at CHUNK-2
        nops1 = bytes([0x90]) * (CHUNK - 2)
        nops2 = bytes([0x90]) * jmp_offset_from_boundary
        padding = bytes([0x90]) * 20
        return nops1 + CROSS + nops2 + self.JMP_MEMCPY + padding

    def _thunk_in_disassembly(self, data):
        d = Disassembler()
        insns = d.disassemble(data, SEC_VA)
        iat_map = {self.MEMCPY_IAT: "memcpy"}
        import capstone.x86 as x86
        for insn in insns:
            if insn.mnemonic != "jmp":
                continue
            cs = insn._cs_insn
            if cs is None:
                continue
            try:
                for op in cs.operands:
                    if (op.type == x86.X86_OP_MEM
                            and op.mem.base == 0
                            and op.mem.index == 0
                            and (op.mem.disp & 0xFFFFFFFF) == self.MEMCPY_IAT):
                        return True
            except Exception:
                pass
        return False

    def test_thunk_found_just_after_cross_boundary_insn(self):
        """JMP [iat] immediately after cross-boundary instruction must be visible."""
        data = self._build(jmp_offset_from_boundary=1)
        assert self._thunk_in_disassembly(data), (
            "Thunk JMP not found when placed just after cross-boundary instruction"
        )

    def test_thunk_found_far_after_cross_boundary_insn(self):
        """JMP [iat] far after the boundary (simulates main.exe distance ~0x1F98)."""
        data = self._build(jmp_offset_from_boundary=0x1F90)
        assert self._thunk_in_disassembly(data), (
            "Thunk JMP not found even far after the cross-boundary instruction"
        )


# ── Test 5: regression on real binaries ───────────────────────────────────────

class TestRealBinaryRegression:
    """
    Scan the uploaded main.exe/main2.exe and verify the CRITICAL finding.
    Skipped when the binaries are not present (CI without uploads).
    """

    MAIN_EXE = "/mnt/user-data/uploads/main.exe"
    MAIN2_EXE = "/mnt/user-data/uploads/main2.exe"

    def _scan_binary(self, path):
        import sys
        sys.path.insert(0, "/home/claude")
        from bo_scanner.pe import parse_pe
        from bo_scanner.disassembler import Disassembler
        from bo_scanner.functions import find_functions
        from bo_scanner.imports import ImportResolver
        from bo_scanner.callsite import analyze_call_sites
        from bo_scanner.scoring import apply_scoring

        pe = parse_pe(path)
        d = Disassembler()
        si = {sec.va: d.disassemble(sec.data, sec.va) for sec in pe.code_sections}
        resolver = ImportResolver(pe, d)
        fns = find_functions(pe.code_sections, si, pe.image_base,
                             export_names=pe.export_names)
        raw = analyze_call_sites(fns, resolver, pe)
        return apply_scoring(raw), resolver

    @pytest.mark.skipif(not os.path.exists("/mnt/user-data/uploads/main.exe"),
                        reason="main.exe not present")
    def test_main_exe_thunks_found(self):
        _, resolver = self._scan_binary(self.MAIN_EXE)
        assert resolver.thunk_count >= 40, (
            f"Expected ≥40 thunks in main.exe, got {resolver.thunk_count} — "
            "chunk-boundary misalignment likely still present"
        )

    @pytest.mark.skipif(not os.path.exists("/mnt/user-data/uploads/main.exe"),
                        reason="main.exe not present")
    def test_main_exe_critical_memcpy_found(self):
        findings, _ = self._scan_binary(self.MAIN_EXE)
        criticals = [f for f in findings if f.severity == "CRITICAL"]
        assert len(criticals) >= 1, "No CRITICAL finding in main.exe — memcpy overflow missed"
        memcpy_crits = [f for f in criticals if f.api_name == "memcpy"]
        assert len(memcpy_crits) >= 1, "CRITICAL memcpy not found in main.exe"

    @pytest.mark.skipif(not os.path.exists("/mnt/user-data/uploads/main.exe"),
                        reason="main.exe not present")
    def test_main_exe_constant_overflow_detected(self):
        findings, _ = self._scan_binary(self.MAIN_EXE)
        overflow_findings = [
            f for f in findings
            if (f.severity == "CRITICAL"
                and f.length is not None
                and f.length.get("imm_value") == 0x4000
                and f.destination.get("estimated_size") is not None
                and f.length["imm_value"] > f.destination["estimated_size"])
        ]
        assert len(overflow_findings) >= 1, (
            "CONSTANT OVERFLOW (0x4000 > buffer size) not detected in main.exe"
        )

    @pytest.mark.skipif(not os.path.exists("/mnt/user-data/uploads/main2.exe"),
                        reason="main2.exe not present")
    def test_main2_exe_critical_memcpy_found(self):
        """Both uploads should yield the same result (they are identical)."""
        findings, _ = self._scan_binary(self.MAIN2_EXE)
        criticals = [f for f in findings if f.severity == "CRITICAL"]
        assert len(criticals) >= 1, "No CRITICAL finding in main2.exe"

    @pytest.mark.skipif(not os.path.exists("/mnt/user-data/uploads/main.exe"),
                        reason="main.exe not present")
    def test_main_exe_instruction_count_correct(self):
        """With the fix, main.exe must produce ≥20000 instructions (was 17500)."""
        from bo_scanner.pe import parse_pe
        from bo_scanner.disassembler import Disassembler
        pe = parse_pe(self.MAIN_EXE)
        d = Disassembler()
        sec = pe.code_sections[0]
        insns = d.disassemble(sec.data, sec.va)
        assert len(insns) >= 20000, (
            f"Only {len(insns)} instructions — chunk boundary fix not applied"
        )
