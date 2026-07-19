#!/usr/bin/env python3
"""
Cyclic pattern generator using a de Bruijn sequence.

Why de Bruijn instead of the classic Metasploit ABC/abc/123 nested-loop approach:
the Metasploit-style generator only guarantees unique 3-char windows for
26*26*10*3 = 20,280 characters. Past that it must repeat, which means a
found offset stops being trustworthy. A de Bruijn sequence over a k-symbol
alphabet with subsequence length n guarantees every n-length window is unique
for the ENTIRE sequence of length k^n, so correctness holds far past 20,280
just by choosing n large enough for your alphabet.
"""
import argparse
import sys

DEFAULT_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
)


def de_bruijn(alphabet, n):
    """
    Generate a de Bruijn sequence B(k, n) over `alphabet` (k = len(alphabet))
    using the standard FKM (Fredricksen-Kessler-Maiorana) algorithm.
    Every substring of length n appears exactly once in the full sequence.
    """
    k = len(alphabet)
    a = [0] * k * n
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in sequence)


def pattern_create(length, alphabet=None, subseq_len=3):
    """
    Build a cyclic pattern of the requested length with guaranteed-unique
    substrings of size `subseq_len`, as long as length <= len(alphabet)**subseq_len.
    """
    if length <= 0:
        raise ValueError("length must be a positive integer")

    if alphabet is None:
        alphabet = DEFAULT_ALPHABET
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must not contain duplicate characters")

    capacity = len(alphabet) ** subseq_len
    if length > capacity:
        raise ValueError(
            f"requested length {length} exceeds unique capacity {capacity} "
            f"for alphabet size {len(alphabet)} and subsequence length {subseq_len}. "
            f"Increase --subseq-len or use a larger alphabet."
        )

    seq = de_bruijn(alphabet, subseq_len)
    # de Bruijn sequences are cyclic by construction: wrap around if the
    # requested length exceeds one period (only relevant right at the edge,
    # since len(seq) == capacity exactly).
    if length <= len(seq):
        return seq[:length]
    reps = (length // len(seq)) + 1
    return (seq * reps)[:length]


def find_offset(pattern, needle, alphabet=None, subseq_len=3):
    """
    Locate `needle` (e.g. bytes read back from a crashed register, as a
    string) inside the generated pattern and return its offset.
    """
    idx = pattern.find(needle)
    if idx == -1:
        raise ValueError(f"{needle!r} not found in pattern")
    return idx


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a de Bruijn based cyclic pattern for buffer-overflow offset finding",
        epilog=(
            "Examples:\n"
            "  pattern_create.py -l 100000\n"
            "  pattern_create.py -l 100000 --offset Aa8Ab8\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-l", "--length", type=int, required=True, help="The length of the pattern")
    parser.add_argument(
        "-a", "--alphabet",
        default=None,
        help="Custom alphabet string (default: A-Z, a-z, 0-9 => capacity 62^n)"
    )
    parser.add_argument(
        "-n", "--subseq-len",
        type=int,
        default=3,
        help="Window size that must stay unique (default: 3, matches EIP/RIP-style 3-4 byte lookups)"
    )
    parser.add_argument(
        "--offset",
        help="Given a substring captured from a crash, print its offset instead of generating a pattern"
    )
    parser.add_argument(
        "--hex",
        help=(
            "Given a raw register value in hex (e.g. 0x42704141 or 42704141), "
            "convert it to bytes using --byte-order and look up its offset. "
            "Overrides --offset."
        )
    )
    parser.add_argument(
        "--byte-order",
        choices=["little", "big"],
        default="little",
        help="Byte order for --hex conversion (default: little, correct for x86/x64 registers)"
    )
    parser.add_argument(
        "--byte-len",
        type=int,
        default=None,
        help="Number of bytes for --hex conversion (default: --subseq-len)"
    )
    return parser.parse_args()


def hex_to_needle(hex_str, byte_order="little", byte_len=None, subseq_len=3):
    hex_str = hex_str.strip()
    if hex_str.lower().startswith("0x"):
        hex_str = hex_str[2:]
    if byte_len is None:
        byte_len = subseq_len
    value = int(hex_str, 16)
    raw = value.to_bytes(byte_len, byteorder=byte_order)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as e:
        raise ValueError(
            f"converted bytes {raw!r} are not printable ASCII; "
            f"double check --byte-order and --byte-len"
        ) from e


def main():
    try:
        args = parse_args()
        pattern = pattern_create(args.length, args.alphabet, args.subseq_len)
        if args.hex:
            needle = hex_to_needle(args.hex, args.byte_order, args.byte_len, args.subseq_len)
            idx = find_offset(pattern, needle, args.alphabet, args.subseq_len)
            print(f"{idx}  (converted {args.hex} -> {needle!r} using {args.byte_order}-endian)")
        elif args.offset:
            idx = find_offset(pattern, args.offset, args.alphabet, args.subseq_len)
            print(idx)
        else:
            print(pattern)
    except Exception as e:
        print(f"[x] {e}", file=sys.stderr)
        print("[*] If necessary, please refer to framework.log for more details.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
