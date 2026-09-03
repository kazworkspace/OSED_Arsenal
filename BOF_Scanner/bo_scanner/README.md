# bo_scanner

Static triage tool for **potential buffer overflows** in 32-bit Windows PE binaries (EXE and DLL).

> **Disclaimer:** This tool performs heuristic static analysis and produces *potential* findings.
> It cannot confirm exploitability. Every finding requires manual review.
> Only analyse binaries you own or have explicit authorisation to test.

---

## Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Python | ≥ 3.8 | Runtime |
| [lief](https://lief-project.github.io/) | ≥ 0.14 | PE parsing, IAT resolution, export table |
| [capstone](https://www.capstone-engine.org/) | ≥ 5.0 | x86 disassembly |
| pytest | ≥ 7.0 | Tests only |

Supported targets: **Windows PE32 (x86 / IA-32)** — EXE, DLL. Packed or encrypted sections will fail.

---

## Installation

```bash
pip install lief capstone

# Optional — only needed to run the test suite
pip install pytest
```

Place `bo_scanner.py` and the `bo_scanner/` folder in the same directory, then run from there.

---

## Quick Start

```bash
# Full scan — default threshold 15%
python bo_scanner.py target.exe

# Verbose: shows function count, IAT entries, raw finding count
python bo_scanner.py target.exe -v

# Focus on one API
python bo_scanner.py target.exe --api strcpy
python bo_scanner.py target.exe --api memcpy
python bo_scanner.py target.exe --api recv
python bo_scanner.py target.exe --api ReadFile

# Drill into one function by address
python bo_scanner.py target.exe --function 0x401800

# Only HIGH and CRITICAL findings
python bo_scanner.py target.exe --min-confidence 0.65

# Show everything including zero-evidence INFO findings
python bo_scanner.py target.exe --min-confidence 0

# Save JSON report
python bo_scanner.py target.exe -o report.json

# JSON only (no human-readable text)
python bo_scanner.py target.exe --json-only -o report.json

# Scan a DLL (same syntax — exported names resolved automatically)
python bo_scanner.py essfunc.dll
```

---

## Understanding the Output

### Severity Scale

| Label | Confidence | Meaning |
|---|---|---|
| **CRITICAL** | ≥ 85% | Overflow statically provable (e.g. constant size > buffer) |
| **HIGH** | ≥ 65% | Strong evidence — stack buffer + attacker-controlled size |
| **MEDIUM** | ≥ 42% | Suspicious but incomplete (heap pointer, missing arg, etc.) |
| **LOW** | ≥ 18% | Weak signal — bounded copy, detected bounds check |
| **INFO** | < 18% | Filtered by default — likely CRT/STL internals |

### Annotated Example

```
[CRITICAL] #1 — Potential Buffer Overflow
  API          : memcpy
  Call site    : 0x0040183F
  Function     : sub_00401800
  Confidence   : 100%

  Destination  :
    [EBP-0x808] — local stack buffer (at most 2056 bytes before EBP)
    estimated size: 2056 bytes (upper bound — frame may hold multiple locals)

  Source       :
    [EBP+0x8] (caller argument #0)              ← network / user input

  Length       :
    0x4000 (immediate constant)
    *** CONSTANT OVERFLOW: copy size 0x4000 (16384) > destination estimate
        0x808 (2056) (8.0× overrun) — STATICALLY PROVABLE ***

  Bounds check :
    NOT DETECTED in lookback window
```

### Destination Types

| Display | Meaning | Risk |
|---|---|---|
| `[EBP-0xN] — local stack buffer` | Stack-allocated buffer | HIGH — return address adjacent |
| `*[EBP-0xN] — pointer … heap` | Pointer to heap buffer | MEDIUM — no adjacent retaddr |
| `[EBP+0xN] (caller argument)` | Pointer from caller | Trace callers — wrapper function |
| `dynamic stack buffer (alloca)` | Frame expanded via alloca() | Stack, but detected frame size is approximate |

### Special Annotations

**`NOTE: Pass-through wrapper`** — all three arguments are caller-provided (`[EBP+0x8]`, `[EBP+0xC]`, `[EBP+0x10]`). The function is a relay. The actual vulnerability is at the callers of this function. Use `--function` on each caller to investigate.

**`NOTE: alloca() detected`** — the function uses dynamic stack expansion. The detected static frame size understates the actual allocation. The destination estimate is approximate but the buffer IS on the stack.

**`*** SIGNED COMPARISON RISK ***`** — the bounds check uses a signed branch (JL/JG/JLE/JGE). A negative size value satisfies a signed check and wraps to `0xFFFFFFFF` when used as `size_t`. This check may be bypassable.

**`*** CONSTANT OVERFLOW ***`** — hardcoded copy size exceeds the detected destination buffer estimate. No dynamic analysis needed — overflow is statically provable.

**`[tail call via JMP]`** — the dangerous API is reached via a JMP rather than CALL (tail-call optimisation). Argument recovery works the same way.

---

## Detected APIs

| Category | APIs |
|---|---|
| Unbounded string copy | `strcpy` `strcat` `gets` `sprintf` `vsprintf` |
| Size-dependent copy | `memcpy` `memmove` `recv` `recvfrom` `ReadFile` `strncpy` `strncat` |
| Formatted input | `scanf` `sscanf` `fscanf` |
| Format string injection | `snprintf` `printf` `fprintf` `vprintf` `vsnprintf` |

**Format string content analysis** — when the format argument is a compile-time constant
address in the binary's `.rdata` section, the tool reads the actual format string and
parses every specifier:

| Pattern | Classification |
|---------|---------------|
| `%s` | **DANGEROUS** — unbounded string read/write |
| `%[^
]` | **DANGEROUS** — unbounded character class scan (signatus pattern) |
| `%n` | **CRITICAL** — write primitive, enables arbitrary memory write |
| `%255s` | safe — width-bounded |
| `%2047[^
]` | safe — width-bounded |
| `%d`, `%x` | safe — numeric, no buffer overflow risk |

CRT-decorated aliases (`_strcpy`, `_memcpy`, …) and Win32 ANSI wrappers (`lstrcpyA`, `lstrcatA`) resolve automatically.

---

## Pipeline

```
PE binary
  ├── pe.py          Parse imports, IAT, export table, code sections
  ├── disassembler.py Chunked capstone x86 disassembly (handles 500+ KB sections)
  ├── functions.py   Function boundary detection
  │     • Prologue byte scan (55 8B EC, 55 89 E5)
  │     • Call-target collection
  │     • Export table VA matching
  ├── imports.py     Dangerous call resolution — 4 patterns:
  │     A  CALL DWORD PTR [iat_va]        (direct IAT, FF 15)
  │     B  CALL thunk → JMP [iat_va]      (debug/incremental builds)
  │     C  JMP [iat_va]                   (tail call)
  │     D  MOV reg, [iat_va]; CALL reg    (C++ / MSVC register-indirect)
  │     + Volatile register awareness (EBX/ESI/EDI trace through CALLs)
  ├── callsite.py    Per-call-site orchestration
  │   ├── dataflow.py  Backward argument recovery — PUSH and MOV[ESP+N]
  │   ├── stack.py     Buffer classification, EspTracker, alloca detection
  │   └── bounds.py    CMP+Jcc detection (signed vs unsigned distinction)
  ├── scoring.py     Risk scoring → CRITICAL / HIGH / MEDIUM / LOW / INFO
  └── report.py      Text + JSON output
```

---

## Calling Convention Support

| Convention | How args are passed | Support |
|---|---|---|
| cdecl | PUSH right-to-left | ✓ Full |
| stdcall | PUSH right-to-left | ✓ Full |
| Framestore (GCC -O0, MSVC) | MOV [ESP+N] | ✓ Full |
| fastcall (ECX/EDX) | Register + PUSH | ✓ ECX/EDX detected as `func_arg_register` |
| Frameless (no EBP frame) | ESP-relative + EspTracker | ✓ Full |

---

## Known Limitations

**Compiler-inlined functions** — When the compiler expands `fscanf` into a `getc` loop (MinGW) or inlines `memcpy` as `REP MOVSD`, there is no IAT entry to match. The vulnerability is invisible to signature-based static analysis.

**Multi-hop data flow** — The scanner traces arguments one call site at a time. `strncpy(buf, src, 3000)` feeding into `Function(buf)` which calls `strcpy(small_buf, buf)` produces two separate findings (INFO for the strncpy, CRITICAL for the strcpy). The connection between them requires manual tracing.

**C++ virtual dispatch** — `CALL EAX` where EAX comes from `[vtable+offset]` cannot be resolved to an API name statically. These appear in the "Unresolved Indirect Calls" section rather than as dangerous findings.

**Heap buffer sizes** — When the destination is a pointer to a `malloc`'d buffer, the scanner marks it `heap_pointer`. It cannot know what size was passed to `malloc`; actual size requires runtime analysis.

**Packed / obfuscated binaries** — If the `.text` section is encrypted at rest, disassembly will fail. Unpack first.

**EBP offset vs. buffer size** — `[EBP-0x40]` means the pointer is 64 bytes before EBP. That 64 bytes is the **entire frame's upper bound**, not the size of a single buffer. Multiple locals share that space.

---

## Test Suite

```bash
pip install pytest
cd bo_scanner/
python -m pytest tests/ -v
```

139 tests covering:
- Argument recovery: PUSH-based, framestore (MOV [ESP+N]), fastcall ECX/EDX
- ESP-relative frameless functions with EspTracker
- Signed vs unsigned bounds-check distinction
- Constant overflow detection
- Pass-through wrapper detection
- Alloca frame inconsistency detection
- Chunked disassembly for large sections (>230 KB)
- Thunk table false-positive filter
- Export table name resolution
- Volatile register awareness in Pattern D backtrack
- Format string rule coverage

---

## Project Structure

```
bo_scanner.py          Entry point
bo_scanner/
  __init__.py
  rules.py             Dangerous API database (categories, arg indices, aliases)
  pe.py                PE parsing — imports, exports, code sections
  disassembler.py      x86 disassembly with chunked large-section support
  functions.py         Function boundary detection
  imports.py           IAT resolution — Patterns A/B/C/D
  dataflow.py          Backward argument recovery (PUSH + framestore)
  stack.py             Buffer classification, EspTracker, alloca detection
  bounds.py            Bounds-check detection (signed/unsigned Jcc)
  callsite.py          Orchestration — call site analysis pipeline
  scoring.py           Risk scoring and severity mapping
  report.py            Text and JSON output
  requirements.txt
  tests/
    conftest.py        Shared byte sequences and helpers
    test_dataflow.py   Argument recovery unit tests
    test_bounds.py     Bounds check detection tests
    test_scoring.py    Scoring logic tests
    test_new_features.py  Fastcall, ESP tracking, indirect call tests
    test_enhancements.py  Framestore, format string, constant overflow tests
    test_regression.py    Cross-binary regression tests
```

---

## Tested Binaries

| Binary | Vulnerability | Result |
|---|---|---|
| `quote_db.exe` | `memcpy(buf[2048], recv_data, 0x4000)` in `log_bad_request` | **CRITICAL 100%** — constant overflow detected |
| `vulnserver.exe` | `strcpy(buf[60–2000], input)` in Function1–4 | **4× CRITICAL** |
| `essfunc.dll` | Same strcpy pattern, exported functions | **5× CRITICAL** with symbol names |
| `signatus.exe` | `fscanf(%[^\n], line[2048])` | **MISSED** — compiler inlined fscanf via getc |
| `rainbow.exe` | HTTP Content-Length → memcpy wrapper → stack overflow | **2× HIGH** with pass-through note |
| `rainbow2.exe` | ReadFile into alloca-based stack buffer | **4× LOW** — bounded reads, alloca note |

---

## License

For educational and research use on binaries you own or have authorisation to test.
