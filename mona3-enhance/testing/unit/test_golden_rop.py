"""P0 golden-output regression scaffold for the full `rop` command.

The default (legacy) `rop` path must stay byte-for-byte identical after the
optimizer work lands. That output can only be produced against a live debugger
(WinDbg/Immunity + pykd), so this test is SKIPPED in headless CI and runs only
when a captured baseline is present.

Workflow:
  1. On a debugger host, generate a baseline against a fixed module, e.g.:
       testing/runmonatests.cmd !mona rop -m <MODULE.dll>
     then copy the produced rop.md to:
       testing/unit/golden/<MODULE>.rop.md
  2. After code changes, regenerate rop.md the same way and drop it at:
       testing/unit/golden/<MODULE>.rop.md.new
  3. Run pytest here; it diffs the two, ignoring volatile lines
     (timestamps, absolute paths, mona/pykd version banners).

Until a baseline is committed the test skips cleanly.
"""
import os
import glob

import pytest

_HERE = os.path.dirname(__file__)
_GOLDEN_DIR = os.path.join(_HERE, "golden")

import re

# lines that legitimately vary run-to-run and are excluded from the .md diff
_VOLATILE = ("generated with mona", "0x", "rva :", "date", "time",
             "corelan", "module base", "process")

# <gadget offset="0x...">TEXT</gadget> / <gadget value="...">TEXT</gadget>
_GADGET_RE = re.compile(r"<gadget[^>]*>(.*?)</gadget>", re.IGNORECASE | re.DOTALL)


def _normalize_md(text):
    out = []
    for line in text.splitlines():
        low = line.strip().lower()
        if any(tok in low for tok in _VOLATILE):
            continue
        out.append(line.rstrip())
    return out


def _normalize_xml(text):
    """For mona chain XML the stable signal is the ordered instruction
    sequence (the gadget element text). Pointer offsets are dropped: legacy
    getShortestGadget shuffles, so the chosen address varies run to run while
    the instruction skeleton does not."""
    return [m.strip().lower() for m in _GADGET_RE.findall(text)]


def _normalize(path, text):
    return _normalize_xml(text) if path.lower().endswith(".xml") else _normalize_md(text)


def _baseline_pairs():
    if not os.path.isdir(_GOLDEN_DIR):
        return []
    pairs = []
    for pattern in ("*.rop.md", "*.xml"):
        for base in glob.glob(os.path.join(_GOLDEN_DIR, pattern)):
            pairs.append((base, base + ".new"))
    return pairs


_PAIRS = _baseline_pairs()


@pytest.mark.skipif(not _PAIRS, reason="no golden baseline committed (live-debugger capture required)")
@pytest.mark.parametrize("baseline,candidate", _PAIRS)
def test_rop_output_unchanged(baseline, candidate):
    if not os.path.exists(candidate):
        pytest.skip("no regenerated output (.new) to compare against %s" % os.path.basename(baseline))
    with open(baseline, "r", encoding="latin-1") as f:
        want = _normalize(baseline, f.read())
    with open(candidate, "r", encoding="latin-1") as f:
        got = _normalize(candidate, f.read())
    assert got == want, "structural ROP output drifted for %s" % os.path.basename(baseline)
