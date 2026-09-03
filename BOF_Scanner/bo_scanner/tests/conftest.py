"""
Shared test helpers.

Tests use REAL capstone disassembly of hand-crafted x86 byte sequences.
No mocking needed — we build actual Instruction objects from real bytes.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import capstone
from bo_scanner.disassembler import Instruction


def make_instructions(code_bytes: bytes, start_va: int = 0x00401000) -> list:
    """Disassemble raw x86 bytes and return a list of Instruction objects."""
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
    result = []
    for insn in cs.disasm(code_bytes, start_va):
        result.append(Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw_bytes=bytes(insn.bytes),
            _cs_insn=insn,
        ))
    return result


# ── Shared byte sequences ────────────────────────────────────────────────────

# Function prologue
PROLOGUE = bytes([
    0x55,           # push ebp
    0x8B, 0xEC,     # mov ebp, esp
    0x83, 0xEC, 0x40,  # sub esp, 0x40  (64-byte frame)
])

# memcpy(dest=[ebp-0x40], src=[ebp+0x08], len=[ebp+0x0c])
# Pushed right-to-left: push len, push src, push dest
MEMCPY_CALL = bytes([
    0x8D, 0x45, 0xC0,     # lea eax, [ebp-0x40]
    0xFF, 0x75, 0x0C,     # push dword ptr [ebp+0x0c]   ; len (arg1 of outer func)
    0xFF, 0x75, 0x08,     # push dword ptr [ebp+0x08]   ; src (arg0 of outer func)
    0x50,                 # push eax                     ; dest = local buffer
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0  (placeholder address)
])

# strcpy(dest=[ebp-0x40], src=constant_string)
STRCPY_CALL = bytes([
    0x8D, 0x45, 0xC0,     # lea eax, [ebp-0x40]
    0x68, 0x00, 0x30, 0x40, 0x00,  # push 0x403000  (constant src)
    0x50,                           # push eax
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
])

# Bounds-checked variant: cmp [ebp+0x0c], 0x40; ja short +5; memcpy(...)
BOUNDED_MEMCPY = bytes([
    0x83, 0x7D, 0x0C, 0x40,  # cmp dword ptr [ebp+0x0c], 0x40
    0x77, 0x0F,               # ja  short 0x0F (reject)
    0x8D, 0x45, 0xC0,         # lea eax, [ebp-0x40]
    0xFF, 0x75, 0x0C,         # push dword ptr [ebp+0x0c]
    0xFF, 0x75, 0x08,         # push dword ptr [ebp+0x08]
    0x50,                     # push eax
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
])
