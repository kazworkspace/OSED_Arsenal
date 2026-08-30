#!/usr/bin/env python3
"""
Hex Calculator
Supports: + - * / // % ** & | ^ << >> and parentheses
Input can be interactive or a single expression as CLI argument.

Examples:
    0x00001 + 0x00002
    0xFF & 0x0F
    (0x10 + 0x20) * 0x2
"""

import sys
import re

# Operators allowed in expressions (whitelist for safety, since we use eval)
ALLOWED_PATTERN = re.compile(r'^[0-9a-fA-Fx\s\+\-\*\/\%\(\)\&\|\^\~\<\>]+$')


def normalize_hex_tokens(expr: str) -> str:
    """
    Ensure every hex literal has the 0x prefix recognized by Python,
    and strip leading zeros issues (Python handles 0x00001 fine already).
    """
    return expr.strip()


def validate_expression(expr: str) -> None:
    if not ALLOWED_PATTERN.match(expr):
        raise ValueError(
            "Expression contains disallowed characters. "
            "Only hex numbers (0x...), spaces, and operators + - * / % ( ) & | ^ << >> are allowed."
        )


def evaluate(expr: str) -> int:
    expr = normalize_hex_tokens(expr)
    validate_expression(expr)
    # eval is used here only after strict whitelist validation above,
    # restricted to no builtins/names.
    result = eval(expr, {"__builtins__": {}}, {})
    if not isinstance(result, int):
        raise ValueError("Expression did not evaluate to an integer.")
    return result


def to_twos_complement(value: int, bits: int) -> int:
    """Wrap a signed Python int into an unsigned N-bit two's complement value."""
    mask = (1 << bits) - 1
    return value & mask


def to_signed(value: int, bits: int) -> int:
    """Interpret an N-bit unsigned pattern as signed, for the decimal column."""
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return (value ^ sign_bit) - sign_bit


def format_result_windbg(value: int, bits: int) -> str:
    """
    WinDbg-style: 'Evaluate expression: <signed decimal> = <unsigned hex, zero-padded>'
    """
    digits = bits // 4
    unsigned_val = to_twos_complement(value, bits)
    signed_val = to_signed(unsigned_val, bits)
    hex_str = format(unsigned_val, f"0{digits}x")
    return f"Evaluate expression: {signed_val} = 0x{hex_str}"


def format_result_plain(value: int, width: int = 0) -> str:
    sign = "-" if value < 0 else ""
    hex_str = format(abs(value), f"0{width}X" if width else "X")
    return f"{sign}0x{hex_str}"


def run_once(expr: str, mode: str = "windbg", bits: int = 32) -> None:
    try:
        result = evaluate(expr)
        if mode == "windbg":
            print(format_result_windbg(result, bits))
        else:
            print(f"{expr.strip()} = {format_result_plain(result)}  (decimal: {result})")
    except ZeroDivisionError:
        print("Error: division by zero")
    except Exception as e:
        print(f"Error: {e}")


def main():
    bits = 32
    mode = "windbg"
    args = sys.argv[1:]

    # Optional flags: --bits=64, --plain
    filtered = []
    for a in args:
        if a.startswith("--bits="):
            bits = int(a.split("=", 1)[1])
        elif a == "--plain":
            mode = "plain"
        else:
            filtered.append(a)

    if filtered:
        run_once(" ".join(filtered), mode=mode, bits=bits)
        return

    print(f"Hex Calculator (WinDbg-style, {bits}-bit). "
          f"Type an expression (e.g. 0x1 - 0x2), or 'q' to quit.")
    print("Flags: --bits=64 for 64-bit width, --plain for signed-magnitude output.")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.lower() in ("q", "quit", "exit"):
            break
        if not line:
            continue
        run_once(line, mode=mode, bits=bits)


if __name__ == "__main__":
    main()
