#!/usr/bin/env python3
"""
pattern_tool.py - Metasploit-compatible cyclic pattern generator/locator

WHAT IT DOES
------------
This combines two common buffer-overflow debugging helpers into one script:
  1. "create" -> generates a De Bruijn-like cyclic pattern (e.g. Aa0Aa1Aa2...),
     used to fill a buffer so every 4-byte chunk is unique.
  2. "offset" -> given a 4-byte value (hex or ASCII, e.g. from a crashed
     EIP/RIP register), finds where in the pattern that value occurs. This
     tells you exactly how many bytes into your buffer the overflow happened.

Both subcommands use the same pattern-generation logic and default character
sets as Metasploit's pattern_create.rb / pattern_offset.rb, so offsets you
find here will match offsets Metasploit would report for the same pattern.

USAGE
-----
1) Generate a pattern of a given length:

    python3 pattern_tool.py create -l 50
    # -> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab

   Optional: use your own character sets instead of the default
   A-Z / a-z / 0-9 (comma-separated groups):

    python3 pattern_tool.py create -l 50 -s ABC,def,123

2) Feed that pattern into your target program's input until it crashes.
   Note the 4-byte value that ended up in the crash register (EIP/RIP, or
   wherever the overflow landed), as either:
     - a hex value, e.g. 0x41326141   (>= 8 hex chars)
     - or the raw 4 ASCII bytes it corresponds to, e.g. Aa3A

3) Look up where that value falls in the pattern:

    python3 pattern_tool.py offset -q Aa3A
    # -> [*] Exact match at offset 9

    python3 pattern_tool.py offset -q 0x41326141

   Use -l to match the same pattern length you generated in step 1, and -s
   to match any custom character sets you used:

    python3 pattern_tool.py offset -q Aa3A -l 8192 -s ABC,def,123

4) If there's no exact match (e.g. the value got shifted by a byte or two
   during the crash), the tool automatically tries nearby single-byte and
   16-bit variations and reports "Possible match" candidates instead.

NOTES
-----
- Length (-l) and sets (-s) must match between "create" and "offset" runs,
  otherwise the offsets won't correspond to the same pattern.
- Default pattern length for "offset" is 8192 if -l is omitted.
"""

import argparse
import sys
import struct
from itertools import product


# -----------------------------
# Pattern creation (same as Metasploit)
# -----------------------------
def pattern_create(length, sets=None):
    if sets is None:
        sets = [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789"
        ]
    else:
        sets = list(sets)

    pattern = []
    for combo in product(*sets):
        for c in combo:
            pattern.append(c)
            if len(pattern) >= length:
                return "".join(pattern[:length])

    return "".join(pattern[:length])


# -----------------------------
# Pattern offset lookup
# -----------------------------
def pattern_offset(buffer, value, start=0):
    val_le = struct.pack("<I", value)
    idx = buffer.find(val_le.decode("latin-1"), start)
    return idx if idx != -1 else None


# -----------------------------
# Query parsing (Ruby-equivalent)
# -----------------------------
def parse_query(query):
    # 8+ hex chars
    if len(query) >= 8:
        try:
            return int(query, 16)
        except ValueError:
            pass

    # 4-byte string
    if len(query) == 4:
        return struct.unpack("<I", query.encode("latin-1"))[0]

    # fallback hex
    return int(query, 16)


# -----------------------------
# "create" subcommand
# -----------------------------
def cmd_create(args):
    result = pattern_create(args.length, args.sets)
    print(result)


# -----------------------------
# "offset" subcommand
# -----------------------------
def cmd_offset(args):
    query = parse_query(args.query)
    buffer = pattern_create(args.length, args.sets)

    offset = pattern_offset(buffer, query)

    # No exact match -> fuzzy matching
    if offset is None:
        found = False
        print("[*] No exact matches, looking for likely candidates...", file=sys.stderr)

        # Single-byte shifts
        for idx in range(4):
            for c in range(256):
                nvb = bytearray(struct.pack("<I", query))
                nvb[idx] = c
                nvi = struct.unpack("<I", nvb)[0]

                off = pattern_offset(buffer, nvi)
                if off is not None:
                    mle = query - struct.unpack("<I", buffer[off:off+4].encode("latin-1"))[0]
                    mbe = query - struct.unpack(">I", buffer[off:off+4].encode("latin-1"))[0]
                    print(
                        f"[+] Possible match at offset {off} "
                        f"(adjusted [ little-endian: {mle} | big-endian: {mbe} ]) "
                        f"byte offset {idx}"
                    )
                    found = True

        if found:
            return

        # 16-bit shifts
        for idx in (0, 2):
            for c in range(65536):
                nvb = bytearray(struct.pack("<I", query))
                nvb[idx:idx+2] = struct.pack("<H", c)
                nvi = struct.unpack("<I", nvb)[0]

                off = pattern_offset(buffer, nvi)
                if off is not None:
                    mle = query - struct.unpack("<I", buffer[off:off+4].encode("latin-1"))[0]
                    mbe = query - struct.unpack(">I", buffer[off:off+4].encode("latin-1"))[0]
                    print(
                        f"[+] Possible match at offset {off} "
                        f"(adjusted [ little-endian: {mle} | big-endian: {mbe} ])"
                    )
                    found = True

        if found:
            return

    # Exact matches (may be multiple)
    while offset is not None:
        print(f"[*] Exact match at offset {offset}")
        offset = pattern_offset(buffer, query, offset + 1)


# -----------------------------
# Argument parsing
# -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Metasploit-compatible cyclic pattern tool (create + offset)",
        epilog="Examples:\n"
               "  pattern_tool.py create -l 50 -s ABC,def,123\n"
               "  pattern_tool.py offset -q Aa3A -l 8192",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # create subcommand
    p_create = subparsers.add_parser("create", help="Generate a cyclic pattern")
    p_create.add_argument(
        "-l", "--length",
        type=int,
        required=True,
        help="The length of the pattern"
    )
    p_create.add_argument(
        "-s", "--sets",
        type=lambda s: s.split(","),
        help="Custom pattern sets (e.g. ABC,def,123)"
    )
    p_create.set_defaults(func=cmd_create)

    # offset subcommand
    p_offset = subparsers.add_parser("offset", help="Find the offset of a value in a cyclic pattern")
    p_offset.add_argument(
        "-q", "--query",
        required=True,
        help="Query to locate (string or hex value)"
    )
    p_offset.add_argument(
        "-l", "--length",
        type=int,
        default=8192,
        help="Length of the pattern (default: 8192)"
    )
    p_offset.add_argument(
        "-s", "--sets",
        type=lambda s: s.split(","),
        help="Custom pattern sets (e.g. ABC,def,123)"
    )
    p_offset.set_defaults(func=cmd_offset)

    return parser.parse_args()


# -----------------------------
# Main logic
# -----------------------------
def main():
    try:
        args = parse_args()
        args.func(args)
    except Exception as e:
        print(f"[x] {e}", file=sys.stderr)
        print("[*] If necessary, please refer to framework.log for more details.", file=sys.stderr)


if __name__ == "__main__":
    main()
