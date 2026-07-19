#!/usr/bin/env python3

import argparse
import sys
from itertools import product

def pattern_create(length, sets=None):
    """
    Equivalent to Rex::Text.pattern_create
    """
    if sets is None:
        # Default Metasploit sets
        sets = [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789"
        ]
    else:
        # User provided sets like: ABC,def,123
        sets = list(sets)

    pattern = []

    for combo in product(*sets):
        for c in combo:
            pattern.append(c)
            if len(pattern) >= length:
                return "".join(pattern[:length])

    return "".join(pattern[:length])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a cyclic pattern (Metasploit compatible)",
        epilog="Example: pattern_create.py -l 50 -s ABC,def,123"
    )

    parser.add_argument(
        "-l", "--length",
        type=int,
        required=True,
        help="The length of the pattern"
    )

    parser.add_argument(
        "-s", "--sets",
        type=lambda s: s.split(","),
        help="Custom pattern sets (e.g. ABC,def,123)"
    )

    return parser.parse_args()


def main():
    try:
        args = parse_args()
        result = pattern_create(args.length, args.sets)
        print(result)
    except Exception as e:
        print(f"[x] {e}", file=sys.stderr)
        print("[*] If necessary, please refer to framework.log for more details.", file=sys.stderr)


if __name__ == "__main__":
    main()
