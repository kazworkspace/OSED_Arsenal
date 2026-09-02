#!/usr/bin/env python3
import argparse

import pykd


def main(args):
    choice_table = {
        "byte": "b",
        "ascii": "a",
        "unicode": "u",
    }

    try:
        search_type, pattern = args.query.split("_", 1)
    except ValueError:
        print("Usage: py search.py <type>_<pattern>")
        return

    if search_type not in choice_table:
        print(f"Unknown search type: {search_type}")
        return

    if search_type == "byte":
        # Remove common prefixes and whitespace
        pattern = pattern.replace("0x", "").replace(" ", "")

        # Must be an even number of hex digits
        if len(pattern) % 2 != 0:
            print("Byte pattern must contain an even number of hex digits.")
            return

        # Convert "41004100" -> "41 00 41 00"
        pattern = " ".join(
            pattern[i:i + 2]
            for i in range(0, len(pattern), 2)
        )

    command = f"s -{choice_table[search_type]} 0 L?80000000 {pattern}"
    print(f"[=] running {command}")

    result = pykd.dbgCommand(command)

    if result is None:
        print("[*] No results returned")
        return

    print(result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search memory."
    )

    parser.add_argument(
        "query",
        help="Format: <type>_<pattern>",
    )

    args = parser.parse_args()
    main(args)
