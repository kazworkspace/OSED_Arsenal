"""P2 unit tests: bad-char retain/soft-exclude classification.

Covers _criteriaBadSet and gadgetPtrBadcharOnly (the retain gate used by the
optimized ROP discovery path). All debugger-free via the integer criteria path.
"""
import pytest


# --- _criteriaBadSet ------------------------------------------------------

def test_badset_from_badchars_bytes(mona):
    assert mona._criteriaBadSet({"badchars": b"\x00\x0a\x0d"}) == {0, 10, 13}


def test_badset_nonull(mona):
    assert mona._criteriaBadSet({"nonull": True}) == {0}


def test_badset_combined(mona):
    assert mona._criteriaBadSet({"badchars": b"\x0a", "nonull": True}) == {0, 10}


def test_badset_empty(mona):
    assert mona._criteriaBadSet({}) == set()


# --- gadgetPtrBadcharOnly -------------------------------------------------

def test_badchar_only_true(mona):
    # 0x10001100 has a 0x00 byte; badchars is the sole failing criterion
    assert mona.gadgetPtrBadcharOnly(0x10001100, {"badchars": b"\x00"}) is True


def test_clean_addr_not_badchar_only(mona):
    # 0x10111213 has no bad byte -> it passes, so "fails only on badchar" is False
    assert mona.gadgetPtrBadcharOnly(0x10111213, {"badchars": b"\x00"}) is False


def test_no_relaxable_criteria(mona):
    assert mona.gadgetPtrBadcharOnly(0x10001100, {}) is False


def test_nonull_relaxed(mona):
    assert mona.gadgetPtrBadcharOnly(0x10001100, {"nonull": True}) is True


def test_syncbreeze_badchar_set(mona):
    # Real target bad-char set used for the Sync Breeze golden runs.
    bc = bytes([0x00, 0x0a, 0x0d, 0x25, 0x26, 0x3d])
    crit = {"badchars": bc}
    assert mona._criteriaBadSet(crit) == {0x00, 0x0a, 0x0d, 0x25, 0x26, 0x3d}
    # address containing 0x25 fails only on badchars -> retained + tagged
    assert mona.gadgetPtrBadcharOnly(0x10250000, crit) is True
    eff = mona.parseGadgetEffect(0x10250000, " # pop eax # retn", badchars=bc)
    assert 0x25 in eff.addr_badchars
    assert eff.score < 0
    # selection avoids the bad-addr gadget when a clean one exists
    pool = {
        0x10250000: " # pop eax # retn",   # 0x25 bad byte
        0x10111213: " # pop eax # retn",   # clean
    }
    mona._rop_opt_ctx = {"badset": mona._criteriaBadSet(crit), "strictbad": False}
    try:
        assert mona.getShortestGadget(pool) == 0x10111213
    finally:
        mona._rop_opt_ctx = None


def test_other_criteria_failure_blocks_retain(mona):
    # Address fails BOTH badchars AND a unicode requirement -> not badchar-only,
    # so it must NOT be retained.
    crit = {"badchars": b"\x00", "unicode": True}
    # 0x41424344 is not unicode and has no 0x00 -> would fail unicode only;
    # pick an address with a 0x00 that also isn't unicode:
    addr = 0x00414243  # has null, not unicode-formatted
    # relaxed (drop badchars/nonull) still requires unicode, which fails
    assert mona.gadgetPtrBadcharOnly(addr, crit) is False
