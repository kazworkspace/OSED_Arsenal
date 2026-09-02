# iat_dump.py -- pykd 0.3.4.15 compatible (x86 / 32-bit focus)
#
# Dump a 32-bit module's Import Address Table from live process memory and print,
# for each import, the IAT *slot address* (the "ptr to Func()" a ROP chain
# needs) alongside the currently-resolved target address and RVA offset.
# If no direct ROP targets are imported, it calculates the offset/delta to target ROP APIs.
#
# Delta = Target_Function - Imported Function
# Usage in WinDbg: !py iat_dump.py module=<modname> [func=VirtualAlloc,...]

import pykd
import sys

# APIs worth calling out for ROP (name match, case-insensitive)
ROP_FUNCS = (
    "virtualalloc", "virtualprotect", "virtualallocex",
    "writeprocessmemory", "loadlibrarya", "getprocaddress"
)


def read_u8(addr):   return pykd.loadBytes(addr, 1)[0]
def read_u16(addr):  return pykd.loadWords(addr, 1)[0]
def read_u32(addr):  return pykd.loadDWords(addr, 1)[0]


def read_cstr(addr):
    try:
        s = pykd.loadCStr(addr)
        return s if s is not None else ""
    except Exception:
        return ""


def fmt_addr(addr):
    """Formats 32-bit address with zero-padding."""
    return f"0x{addr:08X}"


def fmt_rva(rva):
    """Formats RVA offset."""
    return f"+0x{rva:08X}"


def dump_iat(mod, wanted):
    base = mod.begin()

    # PE Header Parsing (x86 / PE32)
    e_lfanew       = read_u32(base + 0x3C)
    ntHeaders      = base + e_lfanew
    optHeaderStart = ntHeaders + 4 + 20             # 4-byte Sig + 20-byte IMAGE_FILE_HEADER
    
    magic = read_u16(optHeaderStart)                # Expect 0x10b for PE32
    if magic == 0x20b:
        print("[!] Warning: Target module appears to be 64-bit (PE32+). Use a 64-bit script variant.")
    
    dataDirOffset = 96                              # PE32 DataDirectory Offset
    importDirAddr = optHeaderStart + dataDirOffset + (1 * 8)  # DataDirectory[1] (Imports)

    importRVA  = read_u32(importDirAddr)
    importSize = read_u32(importDirAddr + 4)

    sep_line = "=" * 80

    print("\n" + sep_line)
    print(f"  MODULE IAT DUMP (x86): {mod.name()}")
    print(sep_line)
    print(f"  Base Address : {fmt_addr(base)}")
    print(f"  Architecture : x86 (32-bit)")
    print(f"  Import Dir   : RVA +0x{importRVA:08X} (Size: {importSize} bytes)")
    print(sep_line)

    if importRVA == 0:
        print("[-] No import directory found for this module.\n")
        return

    descAddr     = base + importRVA
    ORDINAL_FLAG = 0x80000000
    RVA_MASK     = 0x7FFFFFFF
    entrySize    = 4    # 32-bit pointer size
    DESC_SIZE    = 20   # IMAGE_IMPORT_DESCRIPTOR = 5 DWORDs
    max_descs    = (importSize // DESC_SIZE) + 1 if importSize else 4096

    hits = []           # (funcName, iatSlotAddr, iatSlotRVA, resolved)
    all_imports = []    # (dllName, funcName, iatSlotAddr, iatSlotRVA, resolved)
    total_imports = 0

    d = 0
    while d < max_descs:
        descAddr_d     = descAddr + d * DESC_SIZE
        origFirstThunk = read_u32(descAddr_d + 0)
        nameRVA        = read_u32(descAddr_d + 12)
        firstThunk     = read_u32(descAddr_d + 16)

        # Null descriptor terminates the array
        if origFirstThunk == 0 and nameRVA == 0 and firstThunk == 0:
            break
        if nameRVA == 0 or firstThunk == 0:
            d += 1
            continue

        dllName = read_cstr(base + nameRVA)

        print(f"\n[+] Imports from: {dllName}")
        print("-" * 80)
        print(f"  {'IAT Slot Address':<16}  {'RVA Offset':<11}  {'Resolved Target':<16}  Function Name")
        print("-" * 80)

        intRVA  = origFirstThunk if origFirstThunk else firstThunk
        intAddr = base + intRVA
        iatAddr = base + firstThunk

        i = 0
        while True:
            thunkVal = read_u32(intAddr + i * entrySize)
            if thunkVal == 0:
                break

            iatSlotAddr = iatAddr + i * entrySize
            iatSlotRVA  = iatSlotAddr - base
            resolved    = read_u32(iatSlotAddr)

            if thunkVal & ORDINAL_FLAG:
                ordinal  = thunkVal & 0xFFFF
                funcName = f"Ordinal #{ordinal}"
            else:
                nameAddr = base + (thunkVal & RVA_MASK) + 2   # Skip 2-byte Hint
                funcName = read_cstr(nameAddr)

            low = funcName.lower()
            is_rop = (low in ROP_FUNCS or low in wanted)

            rop_tag  = " [★ ROP TARGET]" if is_rop else ""
            slot_str = fmt_addr(iatSlotAddr)
            rva_str  = fmt_rva(iatSlotRVA)
            res_str  = fmt_addr(resolved)

            print(f"  {slot_str:<16}  {rva_str:<11}  {res_str:<16}  {funcName}{rop_tag}")

            all_imports.append((dllName, funcName, iatSlotAddr, iatSlotRVA, resolved))

            if is_rop:
                hits.append((funcName, iatSlotAddr, iatSlotRVA, resolved))

            total_imports += 1
            i += 1

        d += 1

    print("\n" + sep_line)
    print(f"[*] Total Imports Parsed: {total_imports}")

    if hits:
        print("\n" + sep_line)
        print("  [*] ROP-RELEVANT IMPORTS SUMMARY (Target Pointers)")
        print("      (Use 'IAT Slot Address' or 'RVA Offset' as ptr to target API)")
        print(sep_line)
        print(f"  {'IAT Slot Address':<16}  {'RVA Offset':<11}  {'Resolved Target':<16}  Target Function")
        print("-" * 80)
        for name, slot, rva, resolved in hits:
            slot_str = fmt_addr(slot)
            rva_str  = fmt_rva(rva)
            res_str  = fmt_addr(resolved)
            print(f"  {slot_str:<16}  {rva_str:<11}  {res_str:<16}  {name}()")
        print(sep_line + "\n")
    else:
        print("\n" + sep_line)
        print("  [!] No specified ROP-relevant functions found directly in IAT.")
        print("  [*] Calculating deltas from imported functions to target ROP APIs...")
        print("      Formula: Target_API = Imported_API + Delta")
        print(sep_line)

        # Standard ROP target display names
        rop_targets_display = [
            "VirtualAlloc", "VirtualProtect", "VirtualAllocEx",
            "WriteProcessMemory", "LoadLibraryA", "GetProcAddress"
        ]

        # Add user-specified functions from 'wanted' parameter if provided
        for w in wanted:
            if not any(w.lower() == t.lower() for t in rop_targets_display):
                rop_targets_display.append(w)

        symbol_cache = {}

        def resolve_symbol(sym):
            sym_key = sym.lower()
            if sym_key in symbol_cache:
                return symbol_cache[sym_key]
            try:
                addr = pykd.getOffset(sym)
                res = addr if addr != 0 else None
            except Exception:
                res = None
            symbol_cache[sym_key] = res
            return res

        delta_found = False

        for dllName, funcName, slotAddr, slotRVA, resolved in all_imports:
            # Skip ordinal imports or unpopulated/null addresses
            if not funcName or funcName.lower().startswith("ordinal #") or resolved == 0:
                continue

            dll_short = dllName.split('.')[0] if '.' in dllName else dllName

            for target_func in rop_targets_display:
                if funcName.lower() == target_func.lower():
                    continue

                sym_name = f"{dll_short}!{target_func}"
                target_addr = resolve_symbol(sym_name)

                if target_addr and target_addr != 0:
                    delta = target_addr - resolved
                    delta_hex = f"{delta & 0xFFFFFFFF:08X}"
                    delta_dec = f"{delta:+d}"

                    if not delta_found:
                        print(f"  {'Imported Function':<30}  {'Target ROP Function':<30}  {'Delta (Hex)':<12}  {'Delta (Dec)'}")
                        print("-" * 90)
                        delta_found = True

                    imp_sym = f"{dll_short}!{funcName}"
                    targ_sym = f"{dll_short}!{target_func}"
                    print(f"  {imp_sym:<30}  {targ_sym:<30}  {delta_hex:<12}  ({delta_dec})")

        if not delta_found:
            print("  [-] Could not calculate deltas (symbols/APIs could not be resolved).")

        print(sep_line + "\n")


def parse_args(argv):
    mod, funcs = None, set()
    for arg in argv:
        a = arg.lstrip("-")
        if a.startswith("module="):
            mod = a[len("module="):]
        elif a.startswith("func="):
            funcs = set(f.strip().lower() for f in a[len("func="):].split(",") if f.strip())
    return mod, funcs


if __name__ == "__main__":
    modName, wanted = parse_args(sys.argv[1:])

    if not modName:
        print("Usage: !py iat_dump.py module=<module> [func=VirtualAlloc,VirtualProtect]")
        sys.exit(1)

    mod = pykd.module(modName)
    dump_iat(mod, wanted)
