#!/usr/bin/env python3
import re
import sys
import argparse
import tempfile
import subprocess
from pathlib import Path
import multiprocessing
import platform

og_print = print
from rich import print
from rich.tree import Tree
from rich.markup import escape
from ropper import RopperService


def split_file_base(file_arg):
    """
    Split a '-f' argument of the form path[:base_address] into (path, base).

    Uses rsplit on the LAST colon so Windows absolute paths like
    'C:\\Tools\\libspp.dll:0x10000000' are handled correctly (drive-letter
    colon is not mistaken for the base-address separator). Returns
    (path, None) if no base address was supplied.
    """
    if ":" not in file_arg:
        return file_arg, None

    path_part, base_part = file_arg.rsplit(":", 1)

    # Guard against a bare Windows path with no base address, e.g. 'C:\Tools\libspp.dll'
    # (single colon, right-hand side is not a hex/decimal address).
    try:
        int(base_part, 16)
    except ValueError:
        return file_arg, None

    return path_part, base_part


def parse_base_address(base_str):
    """Validate and normalize a base-address string, raising a clear error on failure."""
    try:
        return int(base_str, 16)
    except (TypeError, ValueError):
        raise ValueError(
            f"invalid base address {base_str!r}; expected hex, e.g. 0x10000000"
        )


class Gadgetizer:
    def __init__(self, files, badbytes, output, arch, color):
        self.arch = arch
        self.color = color
        self.files = files
        self.output = output
        self.badbytes = "".join(
            badbytes
        )  # ropper's badbytes option has to be an instance of str
        # file_path -> PE/ELF's own preferred image base, captured before any
        # rebase so we can compute correct addresses ourselves (see _rebase).
        self.default_bases = {}
        # file_path -> user-requested base, only set when ':base' was given
        self.desired_bases = {}
        self.ropper_svc = self.get_ropper_service()
        # store integer addresses so dedup against rp++ is format-agnostic
        self.addresses = set()
        # plain-title -> subtree, so rp++ gadgets can be added post-hoc
        self.category_trees = {}

    def get_ropper_service(self):
        options = {
            "color": self.color,
            "badbytes": self.badbytes,
            "type": "rop",
        }

        rs = RopperService(options)

        for file in self.files:
            file_path, base = split_file_base(file)

            rs.addFile(file_path, arch=self.arch)
            rs.clearCache()

            # NOTE: we deliberately never call rs.setImageBaseFor() here.
            # ropper's setImageBaseFor/-I rebase has a confirmed bug where
            # the resulting gadget address is offset by TWICE the requested
            # delta (new_addr = old_addr + 2*(new_base - old_base)), verified
            # by reproducing it against ropper's own CLI on an unrelated PE.
            # Instead we capture the file's own default image base here and
            # apply the correct, single-delta rebase ourselves in _rebase().
            self.default_bases[file_path] = rs.getFileFor(
                name=file_path
            ).loader.imageBase

            if base is not None:
                self.desired_bases[file_path] = parse_base_address(base)

            rs.loadGadgetsFor(file_path)

        return rs

    def _rebase(self, address, file_path):
        """
        Correctly rebase a ropper-reported address (which always reflects
        the file's own default image base, since we never touch it via
        setImageBaseFor) to the user-requested base, if one was given.
        """
        desired = self.desired_bases.get(file_path)

        if desired is None:
            return address

        default = self.default_bases[file_path]
        return desired + (address - default)

    def _format_gadget(self, gadget, file_path):
        """
        Render a gadget's disassembly string with its address replaced by
        the correctly-rebased address (str(gadget) always uses ropper's raw,
        default-base address since we never call setImageBaseFor).
        """
        rebased = self._rebase(gadget.address, file_path)
        _, _, rest = str(gadget).partition(":")
        return f"0x{rebased:08x}:{rest}"

    def get_gadgets(self, search_str, quality=1, strict=False, gadget_filter=None):
        # filter here (not in caller) so escalation counts only kept gadgets;
        # otherwise a lone filtered quality-1 match blocks the search for
        # usable longer gadgets, leaving a category falsely empty
        gadgets = [
            (f, g)
            for f, g in self.ropper_svc.search(search=search_str, quality=quality)
            if not (gadget_filter and gadget_filter.search(g.simpleString()))
        ]

        if (
            not gadgets
            and quality < self.ropper_svc.options.inst_count
            and not strict
        ):
            return self.get_gadgets(
                search_str, quality=quality + 1, strict=strict,
                gadget_filter=gadget_filter,
            )

        return gadgets

    def _search_gadget(self, title, search_strs):
        plain = title
        tree = Tree(f"[bright_yellow]{title}[/bright_yellow] gadgets")
        gadget_filter = re.compile(r"ret 0x[0-9a-fA-F]{3,};")

        for search_str in search_strs:
            for file, gadget in self.get_gadgets(
                search_str, gadget_filter=gadget_filter
            ):
                tree.add(
                    f"{escape(self._format_gadget(gadget, file)).replace(':', '  #', 1)} :: {file}"
                )
                # keep the correctly-rebased int address for cross-tool dedup
                self.addresses.add(self._rebase(gadget.address, file))

        # register so rp++ gadgets can be appended to the same category later
        self.category_trees[plain] = tree
        return tree

    def _rp_classifiers(self):
        """
        Regex per category, mirroring the ropper search strings, used to
        classify rp++ gadgets (which never pass through ropper's search).
        Matched against a normalized asm string that ends each instr with ';'.
        """
        p = "e" if self.arch == "x86" else "r"
        reg = rf"{p}[a-z0-9]{{1,3}}"
        sp = f"{p}sp"

        specs = [
            ("write-what-where", rf"^mov (?:[a-z]+ ptr )?\[.+?\], \w+;"),
            ("pointer deref", rf"^mov \w+, (?:[a-z]+ ptr )?\[.+?\];"),
            (
                "swap register",
                rf"^(?:mov {reg}, {reg}|xchg {reg}, {reg}|push {reg}; pop {reg});",
            ),
            ("increment register", rf"^inc {reg};"),
            ("decrement register", rf"^dec {reg};"),
            ("add register", rf"^add \w+, {reg};"),
            ("subtract register", rf"^sub \w+, {reg};"),
            ("negate register", rf"^neg {reg};"),
            ("xor register", rf"^xor {reg}, 0x[0-9a-f]+;"),
            ("push", rf"^push {reg};"),
            ("pushad", r"^pushad;"),
            ("pop", rf"^pop {reg};"),
            ("push-pop", rf"^push {reg};.*pop {reg};"),
            (
                "zeroize",
                rf"^(?:xor|sub) ({reg}), \1;|^(?:mov|and) {reg}, 0;|^lea \[?{reg}\]?, 0;",
            ),
            (
                "eip to esp",
                rf"^jmp {sp};|^leave;|^mov {sp}, .+?;|^call {sp};"
                rf"|^xchg {sp}, {reg}; (?:jmp|call) {reg};",
            ),
        ]

        return {title: re.compile(rx) for title, rx in specs}

    def _normalize_rp_asm(self, text):
        """
        Turn an rp++ asm string into ropper's rendering so the category
        regexes and the ret-filter behave identically for both tools.
        e.g. 'add eax, edx ; retn 0x0004' -> 'add eax, edx; ret 4;'
        """
        s = re.sub(r"\s+", " ", text.strip())
        s = re.sub(r"\bretn\b", "ret", s)
        s = re.sub(r"\s*;\s*", "; ", s).strip()
        if not s.endswith(";"):
            s += ";"

        def _fix_ret(m):
            v = m.group(1)
            n = int(v, 16) if v.lower().startswith("0x") else int(v)
            if n == 0:
                return "ret;"
            return f"ret {n};" if n < 10 else f"ret 0x{n:x};"

        return re.sub(r"\bret (0x[0-9a-fA-F]+|\d+);", _fix_ret, s)

    def categorize_rp_gadgets(self, rp_gadgets, file):
        """
        Classify (addr, asm) rp++ gadgets into the existing category subtrees.
        A gadget is added to every category it matches, mirroring how ropper's
        separate per-category searches can list one gadget in several places.
        """
        classifiers = self._rp_classifiers()
        gadget_filter = re.compile(r"ret 0x[0-9a-fA-F]{3,};")

        for addr, text in rp_gadgets:
            norm = self._normalize_rp_asm(text)

            if gadget_filter.search(norm):
                continue

            for title, regex in classifiers.items():
                if not regex.search(norm):
                    continue

                subtree = self.category_trees.get(title)
                if subtree is None:
                    continue

                subtree.add(f"0x{addr:08x}  # {escape(norm)} :: {file}")
                self.addresses.add(addr)

    def add_gadgets_to_tree(self, tree):
        zeroize_strs = []
        reg_prefix = "e" if self.arch == "x86" else "r"

        eip_to_esp_strs = [
            f"jmp {reg_prefix}sp;",
            "leave;",
            f"mov {reg_prefix}sp, ???;",
            f"call {reg_prefix}sp;",
        ]

        tree.add(self._search_gadget("write-what-where", ["mov [???], ???;"]))
        tree.add(self._search_gadget("pointer deref", ["mov ???, [???];"]))
        tree.add(
            self._search_gadget(
                "swap register",
                [
                    "mov ???, ???;",
                    "xchg ???, ???;",
                    "push ???; pop ???;",
                ],
            )
        )
        tree.add(self._search_gadget("increment register", ["inc ???;"]))
        tree.add(self._search_gadget("decrement register", ["dec ???;"]))
        tree.add(
            self._search_gadget(
                "add register",
                [f"add ???, {reg_prefix}??;"],
            )
        )
        tree.add(
            self._search_gadget(
                "subtract register",
                [f"sub ???, {reg_prefix}??;"],
            )
        )
        tree.add(
            self._search_gadget(
                "negate register",
                [f"neg {reg_prefix}??;"],
            )
        )
        tree.add(
            self._search_gadget(
                "xor register",
                [f"xor {reg_prefix}??, 0x????????"],
            )
        )
        tree.add(self._search_gadget("push", [f"push {reg_prefix}??;"]))
        tree.add(self._search_gadget("pushad", ["pushad;"]))
        tree.add(self._search_gadget("pop", [f"pop {reg_prefix}??;"]))
        tree.add(
            self._search_gadget(
                "push-pop",
                [f"push {reg_prefix}??;.*pop {reg_prefix}??;*"],
            )
        )

        for reg in [
            f"{reg_prefix}ax",
            f"{reg_prefix}bx",
            f"{reg_prefix}cx",
            f"{reg_prefix}dx",
            f"{reg_prefix}si",
            f"{reg_prefix}di",
        ]:
            zeroize_strs.append(f"xor {reg}, {reg};")
            zeroize_strs.append(f"sub {reg}, {reg};")
            zeroize_strs.append(f"lea [{reg}], 0;")
            zeroize_strs.append(f"mov {reg}, 0;")
            zeroize_strs.append(f"and {reg}, 0;")

            eip_to_esp_strs.append(
                f"xchg {reg_prefix}sp, {reg}; jmp {reg};"
            )
            eip_to_esp_strs.append(
                f"xchg {reg_prefix}sp, {reg}; call {reg};"
            )

        tree.add(self._search_gadget("zeroize", zeroize_strs))
        tree.add(self._search_gadget("eip to esp", eip_to_esp_strs))

    def save(self):
        self.ropper_svc.options.color = False

        with open(self.output, "w", encoding="utf-8", newline="\n") as f:
            for file in self.files:
                file_path, _base = split_file_base(file)

                for gadget in self.ropper_svc.getFileFor(name=file_path).gadgets:
                    f.write(f"{self._format_gadget(gadget, file_path)}\n")


def add_missing_gadgets(
    ropper_addresses: set,
    in_file,
    outfile,
    bad_bytes,
    rp_path,
    base_address=None,
    collect=False,
):
    """
    Use rp++ to find additional gadgets not found by ropper.

    ropper_addresses is a set of INT addresses. rp++ prints addresses with
    variable width / zero padding, so both sides are normalized to int before
    comparison instead of matching hex strings.

    When collect=True, returns a list of (int_addr, asm_text) for the kept
    rp++-only gadgets so the caller can categorize them.
    """

    collected = []

    rp = Path(rp_path).expanduser().resolve()

    if not rp.exists():
        print("[bright_red][!][/bright_red] rp++ binary not found.")
        print("[bright_yellow][*][/bright_yellow] Download it manually from:")
        print("    https://github.com/0vercl0k/rp")
        return collected

    # On Windows the rp++ binary must be an executable file with a runnable
    # extension; on Linux/macOS it must have the executable bit set. Catching
    # this here avoids an opaque OSError/PermissionError from subprocess.run.
    if platform.system() == "Windows":
        if rp.suffix.lower() != ".exe":
            print(
                f"[bright_red][!][/bright_red] '{rp}' does not look like a "
                f"Windows executable (expected a .exe build of rp++)."
            )
            return collected
    else:
        import os

        if not os.access(rp, os.X_OK):
            print(
                f"[bright_red][!][/bright_red] '{rp}' is not executable. "
                f"Run 'chmod +x {rp}' or download the correct rp++ build for "
                f"this platform: https://github.com/0vercl0k/rp"
            )
            return collected

    with tempfile.TemporaryFile(
        mode="w+", suffix="osed-rop", encoding="utf-8", newline="\n"
    ) as tmp_file, open(outfile, "a", encoding="utf-8", newline="\n") as af:

        command = [
            str(rp),
            "-r5",
            "-f",
            in_file,
            "--unique",
        ]

        if bad_bytes:
            command.append(
                "--bad-bytes=" + "".join(f"\\x{b}" for b in bad_bytes)
            )

        if base_address:
            try:
                parse_base_address(base_address)
            except ValueError as e:
                print(f"[bright_red][!][/bright_red] {e}")
                return collected
            command.append(f"--va={base_address}")

        print(
            f"[bright_green][+][/bright_green] running '{' '.join(command)}'"
        )

        proc = subprocess.run(
            command, stdout=tmp_file, stderr=subprocess.PIPE
        )

        if proc.returncode != 0:
            print(
                f"[bright_red][!][/bright_red] rp++ exited with code "
                f"{proc.returncode}"
            )
            if proc.stderr:
                og_print(proc.stderr.decode(errors="replace").strip())
            return collected

        tmp_file.seek(0)

        for line in tmp_file.readlines():
            if not line.startswith("0x"):
                continue

            try:
                rp_address = int(line.split(":")[0], 16)
            except ValueError:
                continue

            if rp_address not in ropper_addresses:
                truncated = line.rsplit(";", maxsplit=1)[0]
                af.write(f"{truncated}\n")

                if collect:
                    asm = (
                        truncated.split(":", 1)[1]
                        if ":" in truncated
                        else truncated
                    )
                    collected.append((rp_address, asm))

    return collected


def clean_up_all_gadgets(outfile):
    """
    Normalize output from ropper and rp++.
    """

    normal_spaces = re.compile(r"[ ]{2,}")
    normal_semicolon = re.compile(r"[ ]+?;")

    with tempfile.TemporaryFile(
        mode="w+", suffix="osed-rop", encoding="utf-8", newline="\n"
    ) as tmp_file, open(outfile, "r+", encoding="utf-8", newline="\n") as f:

        for line in f.readlines():
            line = normal_spaces.sub(" ", line)
            line = normal_semicolon.sub(";", line)
            line = line.replace(":", "  #", 1)

            tmp_file.write(line)

        tmp_file.seek(0)

        f.seek(0)
        f.write(tmp_file.read())
        f.truncate()


def print_useful_regex(outfile, arch):
    reg_prefix = "e" if arch == "x86" else "r"
    len_sort = (
        "| awk '{ print length, $0 }' "
        "| sort -n -s -r "
        "| cut -d' ' -f2- "
        "| tail"
    )

    any_reg = f"{reg_prefix}.."

    search_terms = [
        f"(jmp|call) {reg_prefix}sp;",
        fr"mov {any_reg}, \[{any_reg}\];",
        fr"mov \[{any_reg}\], {any_reg};",
        fr"mov {any_reg}, {any_reg};",
        fr"xchg {any_reg}, {any_reg};",
        fr"push {any_reg};.*pop {any_reg};",
        fr"inc {any_reg};",
        fr"dec {any_reg};",
        fr"neg {any_reg};",
        fr"push {any_reg};",
        fr"pop {any_reg};",
        "pushad;",
        fr"and {any_reg}, ({any_reg}|0x.+?);",
        fr"xor {any_reg}, ({any_reg}|0x.+?);",
        fr"add {any_reg}, ({any_reg}|0x.+?);",
        fr"sub {any_reg}, ({any_reg}|0x.+?);",
        fr"(lea|mov|and) \[?{any_reg}\]?, 0;",
    ]

    print(
        f"[bright_green][+][/bright_green] helpful regex for searching within {outfile}\n"
    )

    for term in search_terms:
        og_print(f"egrep '{term}' {outfile} {len_sort}")


def main(args):
    if platform.system() == "Darwin":
        # Fix issue with Ropper in macOS
        # AttributeError: 'Ropper' object has no attribute '__gatherGadgetsByEndings'
        multiprocessing.set_start_method("fork")

    g = Gadgetizer(
        args.files,
        args.bad_chars,
        args.output,
        args.arch,
        args.color,
    )

    tree = Tree(
        f'[bright_green][+][/bright_green] Categorized gadgets :: {" ".join(sys.argv)}'
    )

    g.add_gadgets_to_tree(tree)

    print(tree)

    with open(f"{g.output}.clean", "w", encoding="utf-8", newline="\n") as f:
        print(tree, file=f)

    print(
        f"[bright_green][+][/bright_green] Collection of all gadgets written to [bright_blue]{args.output}[/bright_blue]"
    )

    g.save()

    #
    # Run rp++ only if --rp was supplied.
    #
    if args.rp:
        for file in args.files:
            file_path, base = split_file_base(file)

            rp_gadgets = add_missing_gadgets(
                g.addresses,
                file_path,
                args.output,
                bad_bytes=args.bad_chars,
                rp_path=args.rp,
                base_address=base,
                collect=args.categorize_rp,
            )

            if args.categorize_rp and rp_gadgets:
                g.categorize_rp_gadgets(rp_gadgets, file_path)

        clean_up_all_gadgets(args.output)

        # rp++ gadgets were categorized after .clean was first written, so
        # regenerate it (and reprint) to include them
        if args.categorize_rp:
            print(tree)

            with open(f"{g.output}.clean", "w", encoding="utf-8", newline="\n") as f:
                print(tree, file=f)

            print(
                f"[bright_green][+][/bright_green] rp++ gadgets categorized into "
                f"[bright_blue]{g.output}.clean[/bright_blue]"
            )

    print_useful_regex(args.output, args.arch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches for clean, categorized gadgets from a given list of files"
    )

    parser.add_argument(
        "-f",
        "--files",
        help=(
            "space separated list of files from which to pull gadgets "
            "(optionally add a base address, e.g. libspp.dll:0x10000000 or "
            "C:\\Tools\\libspp.dll:0x10000000)"
        ),
        required=True,
        nargs="+",
    )

    parser.add_argument(
        "-b",
        "--bad-chars",
        help=(
            "space separated list of bad chars to omit from gadgets "
            "(default: empty)"
        ),
        default=[],
        nargs="+",
    )

    parser.add_argument(
        "-a",
        "--arch",
        choices=["x86", "x86_64"],
        default="x86",
        help="architecture of the given file (default: x86)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="found-gadgets.txt",
        help="output file for all gadgets",
    )

    parser.add_argument(
        "-c",
        "--color",
        action="store_true",
        help="colorize gadget output",
    )

    parser.add_argument(
        "--rp",
        metavar="PATH",
        default=None,
        help=(
            "path to the rp++ binary "
            "(e.g. ~/.local/bin/rp-lin-x64 or C:\\Tools\\rp.exe)"
        ),
    )

    parser.add_argument(
        "--categorize-rp",
        action="store_true",
        help=(
            "also classify rp++ gadgets into the categorized .clean output "
            "(requires --rp; default: rp++ gadgets go only to the full file)"
        ),
    )

    args = parser.parse_args()

    if args.categorize_rp and not args.rp:
        parser.error("--categorize-rp requires --rp")

    if args.rp:
        rp = Path(args.rp).expanduser()

        if not rp.exists():
            print("[bright_red][!][/bright_red] rp++ binary not found.")
            print("[bright_yellow][*][/bright_yellow] Download it manually from:")
            print("    https://github.com/0vercl0k/rp")
            sys.exit(1)

    main(args)
