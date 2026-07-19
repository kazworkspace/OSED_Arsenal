"""P5 unit tests: module ranking (computeModuleStats / scoreModuleStats / rankModules)."""
import pytest

BADSET = {0x00, 0x0a, 0x0d, 0x25, 0x26, 0x3d}

# addresses with no byte in BADSET
CLEAN = {
    0x10111213: " # pop eax # retn",
    0x10141516: " # pop ebx # retn",
    0x10171819: " # pop ecx # retn",
    0x101b1c1f: " # xchg eax,edx # retn",
}
# module base carries a null -> every address has 0x00
NULLBASE = {
    0x00411213: " # pop eax # retn",
    0x00415617: " # pop ebx # retn",
}
DIRTY = {
    0x18251617: " # pop eax # add esp,0x7210 # retn 0x08",   # addr has 0x25
}


def test_stats_counts(mona):
    st = mona.computeModuleStats(CLEAN, BADSET)
    assert st["total"] == 4
    assert st["clean_frac"] == 1.0
    assert st["pop_regs"] == {"eax", "ebx", "ecx"}
    assert st["cheap"] == 4


def test_nullbase_all_dirty(mona):
    st = mona.computeModuleStats(NULLBASE, BADSET)
    assert st["clean_frac"] == 0.0
    assert st["pop_regs"] == set()      # bad-addr pops don't count


def test_score_rewards_clean_and_api(mona):
    st = mona.computeModuleStats(CLEAN, BADSET)
    base = mona.scoreModuleStats(st, has_api_ptr=False)
    withapi = mona.scoreModuleStats(st, has_api_ptr=True)
    assert withapi == base + 60
    assert base > 0


def test_score_punishes_nullbase(mona):
    st = mona.computeModuleStats(NULLBASE, BADSET)
    assert mona.scoreModuleStats(st) == -100     # clean_frac == 0 penalty


def test_rank_orders_clean_first(mona):
    groups = {"gooddll": CLEAN, "nulldll": NULLBASE, "dirtydll": DIRTY}
    ranked = mona.rankModules(groups, BADSET, api_modules={"gooddll"})
    assert ranked[0][1] == "gooddll"
    assert ranked[0][0] > 0
    assert all(r[0] <= ranked[0][0] for r in ranked)


def test_rank_without_badset(mona):
    # no bad chars -> null-base module addresses are fine, gadgets count
    groups = {"nulldll": NULLBASE}
    ranked = mona.rankModules(groups, badset=None)
    assert ranked[0][2]["clean_frac"] == 1.0
    assert ranked[0][2]["pop_regs"] == {"eax", "ebx"}


def test_report_structure(mona):
    # buildModuleRankReport needs the debugger (belongsTo) for grouping; test the
    # pure pieces via rankModules instead, and just confirm the formatter runs on
    # a pre-grouped path by monkeypatching groupGadgetsByModule.
    groups = {"gooddll": CLEAN, "nulldll": NULLBASE}
    orig = mona.groupGadgetsByModule
    mona.groupGadgetsByModule = lambda rg: groups
    try:
        rep = mona.buildModuleRankReport({}, BADSET, None)
    finally:
        mona.groupGadgetsByModule = orig
    assert "Module ranking" in rep
    assert "gooddll" in rep and "nulldll" in rep
