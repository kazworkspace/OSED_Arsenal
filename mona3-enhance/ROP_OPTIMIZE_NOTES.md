# Mona ROP optimizer — implementation notes

Opt-in, x86-only enhancement to mona's ROP chain generator. Fully backward
compatible: without `-optimize`, `rop` behaves exactly like stock mona.

## Usage

```
!mona rop -m <module> -optimize -cpb '\x00\x0a\x0d...'    # cost-based generator
!mona rop -optimize                                        # all modules
!mona rop -m <module> -optimize -candidates 5              # N ranked candidate routes
!mona rop -m <module> -optimize -strictbad                 # hard-exclude bad-addr gadgets
```

- `-optimize` : enable the cost-based selection engine (x86).
- `-candidates <n>` : emit up to N ranked register-transfer routes (1-10, default 3).
- `-strictbad` : with `-optimize`, discard gadgets whose address has a bad char
  (default keeps them with a large cost penalty).

Extra sections appended to `rop_chains.md` under `-optimize`:
Module ranking, Ranked register-transfer candidates, Value construction advisor.

## What shipped (phases)

| Phase | Capability | Key functions |
|---|---|---|
| P1 | Gadget quality scoring | `GadgetEffect`, `parseGadgetEffect`, `scoreGadget`, `gadgetCost`, `getBestGadget` |
| P2 | Bad-char retain / soft-exclude | `_criteriaBadSet`, `gadgetPtrBadcharOnly`, `_ropPtrRetain` |
| P3 | Register-state Dijkstra search | `buildMoveGraph`, `cheapestRegPath`, `getGadgetMoveRegToRegOpt` |
| P4 | Yen k-shortest ranked candidates | `kCheapestRegPaths`, `buildRegisterCandidateReport` |
| P5 | Module ranking | `computeModuleStats`, `scoreModuleStats`, `rankModules`, `buildModuleRankReport` |
| P6 | Value-construction solver (gadget-bound) | `solveValueToReg`, `putValueInRegOpt`, `_emitValuePlan` |
| P7 | Cross-register value + cheapest move | `putValueViaSourceOpt` |
| P8 | Flexible operand values (dwSize) | `nextCleanValue`, `_ROP_FLEXIBLE`, `_flexibleRegs` |

Selection is switched globally via `_rop_opt_ctx` (set by `createRopChains`
under `-optimize`, reset every call). `getShortestGadget` delegates to
`getBestGadget`; `getGadgetMoveRegToReg` and `putValueInReg` gain opt fast-paths
with legacy fallback. No signatures changed on the ~40 legacy call sites.

## Design principles

- Additive only. Legacy code paths unchanged; new behavior is flag-gated.
- Every solver returns `None` -> legacy fallback, never a crash.
- Flexible-value substitution fires only when the exact value violates the
  ACTUAL bad chars (so `0x201` is kept when `0x00` is not a bad char).
- x86 only; 64-bit and JOP untouched.

## Tests

Debugger-free unit + emit tests under `testing/unit/` (stub `immlib`, no live
debugger). Run:

```
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r testing/unit/requirements-test.txt
./.venv/Scripts/python.exe -m pytest testing/unit/ -q
```

Current: 91 passed, 2 skipped (the 2 skips are live-debugger golden baselines).

Coverage: scoring, bad-char classification, Dijkstra/Yen search, module rank,
value solver (direct/neg/inc-dec/neg-adjust/cross-reg), flexible values, and a
full `createRopChains` emit smoke (XML + Python) that verifies solver output
renders correctly and the expensive eax->ebx move is avoided.

## Known limitations / not done

- Not run on a LIVE target yet — headless tests use synthetic pools + captured
  suggestions. A real `!mona rop -m ... -optimize` run is the pending validation.
- Flexible dwSize picks the smallest null-free value (e.g. `0x01010101` ~16 MB
  when 0x00 is bad); may overrun on some stack VirtualProtect targets. The
  emitted comment shows the substitution + original so it can be adjusted.
- x86 only. No new API recipes beyond mona's built-ins.
- Legacy `optimize=False` end-to-end emit has no dedicated smoke test (guarded
  only by the golden XML baseline, once captured).

## Reference artifacts (testing/)

- `rop_suggestions.md` — real libspp suggestions used for offline validation.
- `libspp_virtual{alloc,protect}.xml` — legacy chain baselines.
- `libspp_optimized_candidates.md` — candidate + value advisor on real data.
- `libspp_emit_sample.txt` — sample emitted Python + XML (synthetic addresses).
