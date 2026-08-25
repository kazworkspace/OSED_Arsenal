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


class Gadgetizer:
    def __init__(self, files, badbytes, output, arch, color):
        self.arch = arch
        self.color = color
        self.files = files
        self.output = output
        self.badbytes = "".join(
            badbytes
        )  # ropper's badbytes option has to be an instance of str
        self.ropper_svc = self.get_ropper_service()
        self.addresses = set()

    def get_ropper_service(self):
        options = {
            "color": self.color,
            "badbytes": self.badbytes,
            "type": "rop",
        }

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

        if (
            not gadgets
            and quality < self.ropper_svc.options.inst_count
            and not strict
        ):
            return self.get_gadgets(search_str, quality=quality + 1)

        return gadgets

    def _search_gadget(self, title, search_strs):
        title = f"[bright_yellow]{title}[/bright_yellow] gadgets"
        tree = Tree(title)
        gadget_filter = re.compile(r"ret 0x[0-9a-fA-F]{3,};")

        for search_str in search_strs:
            for file, gadget in self.get_gadgets(search_str):
                if gadget_filter.search(gadget.simpleString()):
                    continue

                tree.add(
                    f"{escape(str(gadget)).replace(':', '  #', 1)} :: {file}"
                )
                self.addresses.add(hex(gadget.address))

        return tree

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

        with open(self.output, "w") as f:
            for file in self.files:
                if ":" in file:
                    file = file.split(":")[0]

                for gadget in self.ropper_svc.getFileFor(name=file).gadgets:
                    f.write(f"{gadget}\n")
def add_missing_gadgets(
    ropper_addresses: set,
    in_file,
    outfile,
    bad_bytes,
    rp_path,
    base_address=None,
):
    """
    Use rp++ to find additional gadgets not found by ropper.
    """

    rp = Path(rp_path).expanduser().resolve()

    if not rp.exists():
        print("[bright_red][!][/bright_red] rp++ binary not found.")
        print("[bright_yellow][*][/bright_yellow] Download it manually from:")
        print("    https://github.com/0vercl0k/rp")
        return

    with tempfile.TemporaryFile(mode="w+", suffix="osed-rop") as tmp_file, \
         open(outfile, "a") as af:

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
            command.append(f"--va={base_address}")

        print(
            f"[bright_green][+][/bright_green] running '{' '.join(command)}'"
        )

        subprocess.run(command, stdout=tmp_file)

        tmp_file.seek(0)

        for line in tmp_file.readlines():
            if not line.startswith("0x"):
                continue

            rp_address = line.split(":")[0]

            if rp_address not in ropper_addresses:
                truncated = line.rsplit(";", maxsplit=1)[0]
                af.write(f"{truncated}\n")


def clean_up_all_gadgets(outfile):
    """
    Normalize output from ropper and rp++.
    """

    normal_spaces = re.compile(r"[ ]{2,}")
    normal_semicolon = re.compile(r"[ ]+?;")

    with tempfile.TemporaryFile(mode="w+", suffix="osed-rop") as tmp_file, \
         open(outfile, "r+") as f:

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

    with open(f"{g.output}.clean", "w") as f:
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
            if ":" in file:
                file, base = file.split(":")
                add_missing_gadgets(
                    g.addresses,
                    file,
                    args.output,
                    bad_bytes=args.bad_chars,
                    rp_path=args.rp,
                    base_address=base,
                )
            else:
                add_missing_gadgets(
                    g.addresses,
                    file,
                    args.output,
                    bad_bytes=args.bad_chars,
                    rp_path=args.rp,
                )

        clean_up_all_gadgets(args.output)

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
            "(optionally add a base address, e.g. libspp.dll:0x10000000)"
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

    args = parser.parse_args()

    if args.rp:
        rp = Path(args.rp).expanduser()

        if not rp.exists():
            print("[bright_red][!][/bright_red] rp++ binary not found.")
            print("[bright_yellow][*][/bright_yellow] Download it manually from:")
            print("    https://github.com/0vercl0k/rp")
            sys.exit(1)

    main(args)
