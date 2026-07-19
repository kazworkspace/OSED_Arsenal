# mona unit tests (debugger-free)

Pure-function tests for the ROP upgrade. No live debugger required — `conftest.py`
stubs a minimal `immlib` so `mona.py` imports headless with `arch == 32`.

## Run

```
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r testing/unit/requirements-test.txt
./.venv/Scripts/python.exe -m pytest testing/unit/ -q
```

## Layout

- `conftest.py` — headless bootstrap + `mona` session fixture.
- `test_gadget_scoring.py` — P1: `parseGadgetEffect`, `scoreGadget`, `gadgetCost`,
  `getBestGadget`, bad-char soft-exclude, `stack_delta == getJunk` invariant.
- `test_golden_rop.py` — P0: full-`rop` regression scaffold. Skipped until a
  live-debugger baseline is committed to `testing/unit/golden/` (see file header).

## Scope

These cover the additive, dormant P1 primitives only. The legacy `rop` path is
unchanged; the golden scaffold guards it once a baseline module is chosen.
