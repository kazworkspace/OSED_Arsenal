#!/usr/bin/env python3
import re
import sys
import ctypes
import argparse
import tempfile
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from subprocess import CompletedProcess
import multiprocessing
import platform

og_print = print
from rich import print
from rich.tree import Tree
from rich.markup import escape
from ropper import RopperService

# ---------------------------------------------------------------------------
# Download configuration per platform
# ---------------------------------------------------------------------------
# Windows : v2.0.2 direct .exe  (v2.1.5 rp-win.zip ships an ARM64 binary)
# Linux   : v2.1.5 zip          (contains the gcc-built binary)
# macOS   : v2.1.5 zip

_RP_CONFIG = {
    "Linux": {
        "version":      "v2.1.5",
        "url":          "https://github.com/0vercl0k/rp/releases/download/v2.1.5/rp-lin-gcc.zip",
        "is_zip":       True,
        "local_name":   "rp-lin-x64",
        "install_dir":  Path("~/.local/bin").expanduser().resolve(),
    },
    "Darwin": {
        "version":      "v2.1.5",
        "url":          "https://github.com/0vercl0k/rp/releases/download/v2.1.5/rp-osx.zip",
        "is_zip":       True,
        "local_name":   "rp-osx",
        "install_dir":  Path("~/.local/bin").expanduser().resolve(),
    },
    "Windows": {
        "version":      "v2.0.2",
        "url":          "https://github.com/0vercl0k/rp/releases/download/v2.0.2/rp-win-x64.exe",
        "is_zip":       False,
        "local_name":   "rp-win-x64.exe",
        "install_dir":  Path.home() / "AppData" / "Local" / "rp",
    },
}

# PE machine type constants (Windows only)
_PE_MACHINES = {
    0x014c: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0xAA64: "ARM64",
    0x01c4: "ARM Thumb-2",
}
_COMPATIBLE_MACHINES = {0x014c, 0x8664}

# Extensions that are definitely not executable binaries
_TEXT_EXTENSIONS = {".txt", ".md", ".rst", ".pdf", ".json", ".xml", ".yml", ".yaml"}


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def _is_64bit_python():
    """True when the running Python interpreter is 64-bit."""
    return sys.maxsize > 2**32


def _is_wow64():
    """
    True when this process is 32-bit Python running on 64-bit Windows (WOW64).
    Uses PROCESSOR_ARCHITEW6432 env var first (most reliable), then ctypes fallback.
    Note: Windows BOOL is a 4-byte int — must use c_int, NOT c_bool.
    """
    if platform.system() != "Windows":
        return False
    import os
    if "PROCESSOR_ARCHITEW6432" in os.environ:
        return True
    try:
        is_wow64 = ctypes.c_int(0)
        ctypes.windll.kernel32.IsWow64Process(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(is_wow64),
        )
        return bool(is_wow64.value)
    except Exception:
        return False


def _can_run_64bit_binary():
    """
    True if this process can successfully spawn a 64-bit binary.
      64-bit Python on 64-bit Windows  -> True  (direct)
      32-bit Python on 64-bit Windows  -> True  (WOW64, cmd.exe workaround)
      32-bit Python on 32-bit Windows  -> False
    Always True on Linux/macOS.
    """
    if platform.system() != "Windows":
        return True
    return _is_64bit_python() or _is_wow64()


def _pe_machine_type(path):
    """
    Reads the PE machine type from a Windows executable.
    Returns (machine_int, description_str) or (None, error_str) on failure.
    """
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return None, "Not a valid PE (missing MZ header)"
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), "little")
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return None, "Not a valid PE (missing PE signature)"
            machine = int.from_bytes(f.read(2), "little")
            return machine, _PE_MACHINES.get(machine, f"Unknown (0x{machine:04x})")
    except Exception as e:
        return None, str(e)


def _run_subprocess(command):
    """
    Runs command (list) and returns a CompletedProcess.
    On 32-bit Python + 64-bit Windows (WOW64): routes through cmd.exe so the
    64-bit rp++ binary can be spawned from a 32-bit Python process.
    WinError 216 (machine type mismatch) is caught and diagnosed gracefully.
    """
    try:
        if platform.system() == "Windows" and not _is_64bit_python() and _is_wow64():
            # Route through 64-bit cmd.exe so 32-bit Python can spawn 64-bit binary
            cmd_str = subprocess.list2cmdline(command)
            return subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
        return subprocess.run(command, capture_output=True, text=True)

    except OSError as e:
        if hasattr(e, "winerror") and e.winerror == 216:
            machine, desc = _pe_machine_type(command[0])
            print(f"\n[bright_red][!][/bright_red] WinError 216: architecture mismatch.")
            print(f"    Binary: {command[0]}")
            print(f"    PE machine type: {desc}")
            print(f"    Delete the binary and re-run, or use --skip-rp.")
            return CompletedProcess(command, returncode=1, stdout="", stderr=str(e))
        raise


# ---------------------------------------------------------------------------
# rp++ download and extraction
# ---------------------------------------------------------------------------

def _extract_from_zip(zip_path, dest_path):
    """
    Extracts the rp++ binary from a zip archive to dest_path.
    Picks the first file that looks like an executable (not a directory or text file).
    Prefers entries whose name starts with 'rp' when multiple candidates exist.
    Returns True on success, False on failure.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        contents = zf.namelist()
        print(f"[bright_green][+][/bright_green] Archive contents: {contents}")

        candidates = [
            n for n in contents
            if not n.endswith("/")                              # skip directories
            and Path(n).suffix.lower() not in _TEXT_EXTENSIONS # skip docs
            and not Path(n).name.startswith(".")               # skip hidden files
        ]

        if not candidates:
            print(f"[bright_red][!][/bright_red] No executable found in archive.")
            return False

        # Prefer entries whose filename starts with 'rp'
        rp_matches = [c for c in candidates if Path(c).name.lower().startswith("rp")]
        chosen = rp_matches[0] if rp_matches else candidates[0]

        print(f"[bright_green][+][/bright_green] Extracting '{chosen}' -> {dest_path}")
        with zf.open(chosen) as src, open(dest_path, "wb") as dst:
            dst.write(src.read())

    return True


def get_rp_binary():
    """
    Returns (rp_path, config) for the current platform.
    Raises RuntimeError on unsupported or incompatible platforms.
    """
    system = platform.system()

    if system not in _RP_CONFIG:
        raise RuntimeError(f"Unsupported platform: {system}")

    if system == "Windows" and not _can_run_64bit_binary():
        raise RuntimeError(
            "rp++ requires 64-bit Windows. Use --skip-rp to skip the rp++ step."
        )

    cfg = _RP_CONFIG[system]
    rp_path = cfg["install_dir"] / cfg["local_name"]
    return rp_path, cfg


def download_rp(rp_path, cfg):
    """
    Downloads rp++ for the current platform.
    Handles both direct binary downloads and zip archives transparently.
    Sets executable bit on Linux/macOS.
    """
    url     = cfg["url"]
    version = cfg["version"]
    is_zip  = cfg["is_zip"]

    rp_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[bright_yellow][*][/bright_yellow] rp++ not found, downloading {version}...")
    print(f"[bright_green][+][/bright_green] URL: {url}")

    try:
        if is_zip:
            zip_path = rp_path.parent / Path(url).name
            urllib.request.urlretrieve(url, zip_path)
            success = _extract_from_zip(zip_path, rp_path)
            zip_path.unlink(missing_ok=True)
            if not success:
                return False
        else:
            urllib.request.urlretrieve(url, rp_path)

    except Exception as e:
        print(f"[bright_red][!][/bright_red] Download failed: {e}")
        print(f"    Download manually from {url} to {rp_path}, "
              f"or use --skip-rp to skip rp++.")
        return False

    # Set executable bit on Linux/macOS (no-op on Windows)
    if platform.system() != "Windows":
        rp_path.chmod(mode=0o755)

    # On Windows, verify the PE machine type immediately after download
    if platform.system() == "Windows":
        machine, desc = _pe_machine_type(rp_path)
        print(f"[bright_green][+][/bright_green] Downloaded: {rp_path}")
        print(f"[bright_green][+][/bright_green] PE machine type: {desc}")
        if machine not in _COMPATIBLE_MACHINES:
            print(f"[bright_red][!][/bright_red] Incompatible binary ({desc}) — "
                  f"cannot run on x86/x64 Windows.")
            rp_path.unlink(missing_ok=True)
            return False
    else:
        print(f"[bright_green][+][/bright_green] rp++ ready at {rp_path}")

    return True


def add_missing_gadgets(ropper_addresses: set, in_file, outfile, bad_bytes, base_address=None):
    """
    rp++ finds significantly more gadgets than ropper alone.
    Appends any addresses not already found by ropper.
    Supports Windows (x86/x64), Linux, and macOS.
    """
    try:
        rp, cfg = get_rp_binary()
    except RuntimeError as e:
        print(f"[bright_red][!][/bright_red] {e}")
        return

    if not rp.exists():
        if not download_rp(rp, cfg):
            return

    # On Windows, verify machine type before running (catches a stale bad download)
    if platform.system() == "Windows":
        machine, desc = _pe_machine_type(rp)
        if machine is not None and machine not in _COMPATIBLE_MACHINES:
            print(f"[bright_red][!][/bright_red] Skipping rp++: {rp.name} is {desc}, "
                  f"incompatible with x86/x64 Windows.")
            print(f"    Delete {rp} and re-run to trigger a fresh download.")
            return

    command = [str(rp), "--file", in_file, "--unique"]

    if bad_bytes:
        bad_bytes_str = "".join([f"\\x{byte}" for byte in bad_bytes])
        command.append(f"--bad-bytes={bad_bytes_str}")
    if base_address:
        command.append(f"--va={base_address}")

    print(f"[bright_green][+][/bright_green] running '{' '.join(command)}'")

    result = _run_subprocess(command)

    if result.returncode != 0 and result.stderr:
        print(f"[bright_red][!][/bright_red] rp++ stderr: {result.stderr.strip()}")

    with open(outfile, "a") as af:
        for line in result.stdout.splitlines():
            if not line.startswith("0x"):
                continue
            rp_address = line.split(":")[0]
            if rp_address not in ropper_addresses:
                truncated = line.rsplit(";", maxsplit=1)[0]
                af.write(f"{truncated}\n")


# ---------------------------------------------------------------------------
# Gadgetizer
# ---------------------------------------------------------------------------

class Gadgetizer:
    def __init__(self, files, badbytes, output, arch, color):
        self.arch = arch
        self.color = color
        self.files = files
        self.output = output
        self.badbytes = "".join(badbytes)
        self.ropper_svc = self.get_ropper_service()
        self.addresses = set()

    def get_ropper_service(self):
        options = {"color": self.color, "badbytes": self.badbytes, "type": "rop"}
        rs = RopperService(options)
        for file in self.files:
            if ":" in file:
                file, base = file.split(":")
                rs.addFile(file, arch=self.arch)
                rs.clearCache()
                rs.setImageBaseFor(name=file, imagebase=int(base, 16))
            else:
                rs.addFile(file, arch=self.arch)
                rs.clearCache()
            rs.loadGadgetsFor(file)
        return rs

    def get_gadgets(self, search_str, quality=1, strict=False):
        gadgets = [
            (f, g)
            for f, g in self.ropper_svc.search(search=search_str, quality=quality)
        ]
        if not gadgets and quality < self.ropper_svc.options.inst_count and not strict:
            return self.get_gadgets(search_str, quality=quality + 1)
        return gadgets

    def _search_gadget(self, title, search_strs):
        title = f"[bright_yellow]{title}[/bright_yellow] gadgets"
        tree = Tree(title)
        gadget_filter = re.compile(r'ret 0x[0-9a-fA-F]{3,};')
        for search_str in search_strs:
            for file, gadget in self.get_gadgets(search_str):
                if gadget_filter.search(gadget.simpleString()):
                    continue
                tree.add(f"{escape(str(gadget)).replace(':', '  #', 1)} :: {file}")
                self.addresses.add(hex(gadget.address))
        return tree

    def add_gadgets_to_tree(self, tree):
        zeroize_strs = []
        reg_prefix = "e" if self.arch == "x86" else "r"
        eip_to_esp_strs = [
            f"jmp {reg_prefix}sp;", "leave;",
            f"mov {reg_prefix}sp, ???;", f"call {reg_prefix}sp;",
        ]
        tree.add(self._search_gadget("write-what-where", ["mov [???], ???;"]))
        tree.add(self._search_gadget("pointer deref", ["mov ???, [???];"]))
        tree.add(self._search_gadget("swap register",
            ["mov ???, ???;", "xchg ???, ???;", "push ???; pop ???;"]))
        tree.add(self._search_gadget("increment register", ["inc ???;"]))
        tree.add(self._search_gadget("decrement register", ["dec ???;"]))
        tree.add(self._search_gadget("add register", [f"add ???, {reg_prefix}??;"]))
        tree.add(self._search_gadget("subtract register", [f"sub ???, {reg_prefix}??;"]))
        tree.add(self._search_gadget("negate register", [f"neg {reg_prefix}??;"]))
        tree.add(self._search_gadget("xor register", [f"xor {reg_prefix}??, 0x????????"]))
        tree.add(self._search_gadget("push", [f"push {reg_prefix}??;"]))
        tree.add(self._search_gadget("pushad", [f"pushad;"]))
        tree.add(self._search_gadget("pop", [f"pop {reg_prefix}??;"]))
        tree.add(self._search_gadget("push-pop",
            [f"push {reg_prefix}??;.*pop {reg_prefix}??;*"]))
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx",
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            zeroize_strs.extend([
                f"xor {reg}, {reg};", f"sub {reg}, {reg};",
                f"lea [{reg}], 0;", f"mov {reg}, 0;", f"and {reg}, 0;",
            ])
            eip_to_esp_strs.extend([
                f"xchg {reg_prefix}sp, {reg}; jmp {reg};",
                f"xchg {reg_prefix}sp, {reg}; call {reg};",
            ])
        tree.add(self._search_gadget("zeroize", zeroize_strs))
        tree.add(self._search_gadget("eip to esp", eip_to_esp_strs))

    def save(self):
        self.ropper_svc.options.color = False
        with open(self.output, "w") as f:
            for file in self.files:
                if ":" in file:
                    file = file.split(":")[0]
                for gadget in self.ropper_svc.getFileFor(name=file).gadgets:
                    f.write(f"{gadget}\n")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def clean_up_all_gadgets(outfile):
    """Normalize output from ropper and rp++."""
    normal_spaces = re.compile(r'[ ]{2,}')
    normal_semicolon = re.compile(r'[ ]+?;')

    with tempfile.TemporaryFile(mode='w+', suffix='osed-rop') as tmp_file, \
         open(outfile, 'r+') as f:
        for line in f.readlines():
            line = normal_spaces.sub(' ', line)
            line = normal_semicolon.sub(';', line)
            line = line.replace(':', '  #', 1)
            tmp_file.write(line)
        tmp_file.seek(0)
        f.seek(0)
        f.write(tmp_file.read())
        f.truncate()


def print_useful_regex(outfile, arch):
    reg_prefix = "e" if arch == "x86" else "r"
    len_sort = "| awk '{ print length, $0 }' | sort -n -s -r | cut -d' ' -f2- | tail"
    any_reg = f'{reg_prefix}..'

    search_terms = [
        f'(jmp|call) {reg_prefix}sp;',
        fr'mov {any_reg}, \[{any_reg}\];',
        fr'mov \[{any_reg}\], {any_reg};',
        fr'mov {any_reg}, {any_reg};',
        fr'xchg {any_reg}, {any_reg};',
        fr'push {any_reg};.*pop {any_reg};',
        fr'inc {any_reg};', fr'dec {any_reg};', fr'neg {any_reg};',
        fr'push {any_reg};', fr'pop {any_reg};', 'pushad;',
        fr'and {any_reg}, ({any_reg}|0x.+?);',
        fr'xor {any_reg}, ({any_reg}|0x.+?);',
        fr'add {any_reg}, ({any_reg}|0x.+?);',
        fr'sub {any_reg}, ({any_reg}|0x.+?);',
        fr'(lea|mov|and) \[?{any_reg}\]?, 0;',
    ]

    print(f"[bright_green][+][/bright_green] helpful regex for searching within {outfile}\n")
    # awk/sort/cut are Unix tools. On Windows: findstr /R "<pattern>" <outfile>
    for term in search_terms:
        og_print(f"egrep '{term}' {outfile} {len_sort}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(args):
    if platform.system() == 'Darwin':
        # Fix Ropper macOS issue:
        # AttributeError: 'Ropper' object has no attribute '__gatherGadgetsByEndings'
        multiprocessing.set_start_method('fork')

    g = Gadgetizer(args.files, args.bad_chars, args.output, args.arch, args.color)

    tree = Tree(
        f'[bright_green][+][/bright_green] Categorized gadgets :: {" ".join(sys.argv)}'
    )
    g.add_gadgets_to_tree(tree)
    print(tree)

    with open(f"{g.output}.clean", "w") as f:
        print(tree, file=f)

    print(f"[bright_green][+][/bright_green] Collection of all gadgets written to "
          f"[bright_blue]{args.output}[/bright_blue]")
    g.save()

    if args.skip_rp:
        return

    for file in args.files:
        if ":" in file:
            file, base = file.split(":")
            add_missing_gadgets(g.addresses, file, args.output,
                                bad_bytes=args.bad_chars, base_address=base)
        else:
            add_missing_gadgets(g.addresses, file, args.output,
                                bad_bytes=args.bad_chars)

    clean_up_all_gadgets(args.output)
    print_useful_regex(args.output, args.arch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches for clean, categorized gadgets from a given list of files"
    )
    parser.add_argument("-f", "--files",
        help="space separated list of files (optionally: libspp.dll:0x10000000)",
        required=True, nargs="+")
    parser.add_argument("-b", "--bad-chars",
        help="space separated bad chars to omit, e.g., 00 0a (default: empty)",
        default=[], nargs="+")
    parser.add_argument("-a", "--arch",
        choices=["x86", "x86_64"], default="x86",
        help="architecture of the given file (default: x86)")
    parser.add_argument("-o", "--output",
        default="found-gadgets.txt",
        help="output file for all uncategorized gadgets (default: found-gadgets.txt)")
    parser.add_argument("-c", "--color",
        help="colorize gadgets in output (default: False)", action='store_true')
    parser.add_argument("-s", "--skip-rp",
        help="skip rp++ supplemental gadget search (default: False)",
        action='store_true')

    args = parser.parse_args()
    main(args)
