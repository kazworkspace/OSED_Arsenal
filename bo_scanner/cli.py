"""
CLI: argument parsing and main analysis pipeline.

Pipeline:
  PE file
    → parse_pe()         [pe.py]
    → Disassembler       [disassembler.py]
    → find_functions()   [functions.py]
    → ImportResolver     [imports.py]
    → analyze_call_sites()[callsite.py]
    → apply_scoring()    [scoring.py]
    → text + JSON report [report.py]
"""
import argparse
import json
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bo_scanner",
        description="Static triage tool: potential buffer overflows in x86 Windows PE binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bo_scanner.py sample.exe
  python bo_scanner.py sample.exe -o report.json -v
  python bo_scanner.py sample.exe --api memcpy --min-confidence 0.6
  python bo_scanner.py sample.exe --function 0x401230
  python bo_scanner.py sample.exe --json-only -o out.json
        """,
    )
    p.add_argument("binary",          help="Path to 32-bit Windows PE binary")
    p.add_argument("-o", "--output",  help="Write JSON report to FILE", metavar="FILE")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output")
    p.add_argument(
        "--function",
        help="Analyse only the function at this hex address (e.g. 0x401230)",
        metavar="ADDR",
    )
    p.add_argument(
        "--api",
        help="Filter results to a specific API (e.g. memcpy, strcpy)",
        metavar="NAME",
    )
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.15,
        metavar="N",
        help="Only show findings with confidence >= N  (0.0–1.0, default 0.15; use 0 for all)",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Print only JSON (no human-readable text report)",
    )
    return p


def run(argv=None) -> int:
    """Entry point. Returns exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    _err = lambda msg: print(f"[ERROR] {msg}", file=sys.stderr)
    _log = lambda msg: print(f"[*] {msg}", file=sys.stderr) if args.verbose else None
    _info = lambda msg: print(f"[*] {msg}", file=sys.stderr)

    if not Path(args.binary).exists():
        _err(f"File not found: {args.binary}")
        return 1

    # ── Imports (inside run() to give useful errors on missing deps) ──────────
    try:
        from .pe import parse_pe
        from .disassembler import Disassembler
        from .functions import find_functions
        from .imports import ImportResolver
        from .callsite import analyze_call_sites
        from .scoring import apply_scoring
        from .report import format_text_report, format_json_report
    except ImportError as exc:
        _err(f"Missing dependency: {exc}")
        _err("Install with:  pip install lief capstone")
        return 1

    # ── Parse PE ──────────────────────────────────────────────────────────────
    _info(f"Loading: {args.binary}")
    try:
        pe = parse_pe(args.binary)
    except ValueError as exc:
        _err(str(exc))
        return 1

    if args.verbose:
        print(f"    Image base   : 0x{pe.image_base:08X}", file=sys.stderr)
        print(f"    Entry point  : 0x{pe.entry_point_va:08X}", file=sys.stderr)
        print(f"    Imports      : {len(pe.imports)}", file=sys.stderr)
        print(f"    Exports      : {len(pe.export_names)}", file=sys.stderr)
        print(f"    Code sections: {len(pe.code_sections)}", file=sys.stderr)
        for sec in pe.code_sections:
            print(f"      {sec.name:8s}  VA=0x{sec.va:08X}  size={sec.size}", file=sys.stderr)

    # ── Disassemble ───────────────────────────────────────────────────────────
    _info("Disassembling code sections...")
    disasm = Disassembler()
    section_insns = {}
    for sec in pe.code_sections:
        insns = disasm.disassemble(sec.data, sec.va)
        section_insns[sec.va] = insns
        _log(f"  {sec.name}: {len(insns)} instructions")

    # ── Resolve imports + thunks ──────────────────────────────────────────────
    _info("Resolving imports and thunks...")
    resolver = ImportResolver(pe, disasm)
    _log(f"  IAT entries : {len(pe.iat_map)}")
    _log(f"  Thunks found: {resolver.thunk_count}")

    # ── Find functions ────────────────────────────────────────────────────────
    _info("Detecting function boundaries...")
    export_names = pe.export_names  # VA → exported symbol name (empty for stripped EXEs)
    functions = find_functions(
        pe.code_sections, section_insns, pe.image_base,
        export_vas=set(export_names.keys()) if export_names else None,
        export_names=export_names,
    )
    _info(f"Functions found: {len(functions)}")

    # ── Apply function filter ─────────────────────────────────────────────────
    filter_func_va = None
    if args.function:
        try:
            filter_func_va = int(args.function, 16)
        except ValueError:
            _err(f"Invalid hex address: {args.function}")
            return 1
        matching = [f for f in functions if f.start_va == filter_func_va]
        if not matching:
            _err(f"No function detected at 0x{filter_func_va:08X}")
            return 1
        _info(f"Filtering to function: sub_{filter_func_va:08X}")

    # ── Analyse call sites ────────────────────────────────────────────────────
    _info("Analysing call sites...")
    raw_findings = analyze_call_sites(
        functions, resolver, pe,
        filter_api=args.api,
        filter_func_va=filter_func_va,
    )

    # ── Score and sort ────────────────────────────────────────────────────────
    findings = apply_scoring(raw_findings)
    _log(f"  Total raw findings : {len(findings)}")

    # Filter by confidence threshold
    filtered = [f for f in findings if f.confidence >= args.min_confidence]
    _info(f"Findings above threshold ({args.min_confidence:.0%}): {len(filtered)}")

    # ── Output ────────────────────────────────────────────────────────────────
    if not args.json_only:
        text = format_text_report(filtered, pe.filename, min_confidence=0.0)
        print(text)

    json_data = format_json_report(filtered, pe.filename, min_confidence=0.0)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=2)
        _info(f"JSON report written to: {args.output}")

    if args.json_only:
        print(json.dumps(json_data, indent=2))

    return 0
