# Golden ROP baselines

Locks the **legacy** `rop` output so the optimizer work (P3+) cannot silently
change default behavior. Baselines must be captured on a live-debugger host —
they cannot be produced headless.

## Targets (chosen)

| Target | File | Notes |
|---|---|---|
| `libspp.dll` | `testing/libspp.dll` | Sync Breeze module — rich x86 gadget set |
| `syncbrs.exe` | `testing/syncbrs.exe` | Sync Breeze main image |

## Capture (on a WinDbg/Immunity host)

Load the target so the module is mapped, then run the **legacy** command (no
`-optimize`) and copy the produced `rop.md`:

```
# baseline (legacy, default path)
testing/runmonatests.cmd !mona rop -m libspp.dll
copy <workingfolder>\rop.md testing/unit/golden/libspp.rop.md

testing/runmonatests.cmd !mona rop -m syncbrs.exe
copy <workingfolder>\rop.md testing/unit/golden/syncbrs.rop.md
```

## Optimized run (compare against legacy)

Same target, cost-based generator, Sync Breeze bad-char set:

```
!mona rop -m libspp.dll -optimize -cpb '\x00\x0a\x0d\x25\x26\x3d'
!mona rop -m libspp.dll -optimize -candidates 5 -cpb '\x00\x0a\x0d\x25\x26\x3d'
!mona rop -m libspp.dll -optimize -strictbad -cpb '\x00\x0a\x0d\x25\x26\x3d'   # hard-exclude bad-addr
```

`-cpb` populates `criteria["badchars"]`; under `-optimize` bad-address gadgets
are kept with a large cost penalty instead of being discarded (unless
`-strictbad`).

## Regression check (after code changes)

Regenerate the same way, save as `*.rop.md.new`, then:

```
python -m pytest testing/unit/test_golden_rop.py -q
```

`test_golden_rop.py` diffs `<name>.rop.md` vs `<name>.rop.md.new`, ignoring
volatile lines (addresses, RVAs, timestamps, banners). Commit only the
`.rop.md` baselines; `*.new` is git-ignored.
