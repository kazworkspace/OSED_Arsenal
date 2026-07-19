"""P1 unit tests: GadgetEffect parsing, scoreGadget, getBestGadget.

All debugger-free. Gadget strings use mona's ' # ' convention where the last
segment is the ending token ('retn' == clean ret, 'retn 0xNN' == ret N).
"""
import pytest


# --- scoreGadget: the two spec anchor examples ---------------------------

def test_good_gadget_outranks_bad(mona):
    good = mona.parseGadgetEffect(0x10001000, " # pop eax # retn")
    bad = mona.parseGadgetEffect(
        0x10002000,
        " # push eax # add al,0x5d # mov eax,0x1 # pop ebx # add esp,0x7210 # retn 0x08",
    )
    assert good.score > bad.score
    assert good.score > 100      # single-purpose + clean ret bonus
    assert bad.score < 0         # heavily penalized


def test_clean_pop_ret_bonus(mona):
    eff = mona.parseGadgetEffect(0x1000, " # pop eax # retn")
    assert eff.ending_kind == "ret_clean"
    assert eff.ending_off == 0
    assert eff.reg_writes["eax"] == mona.SYM_VALUE(None)
    assert eff.mem_writes == 0
    assert eff.score == 120      # 100 + 20 bonus


# --- ending classification ------------------------------------------------

@pytest.mark.parametrize("chain,kind,off", [
    (" # pop eax # retn", "ret_clean", 0),
    (" # pop eax # retn 0x08", "ret_n", 8),
    (" # pop eax # retn 0x10", "ret_n", 16),
    (" # jmp eax", "other", 0),
])
def test_ending_classification(mona, chain, kind, off):
    eff = mona.parseGadgetEffect(0x1000, chain)
    assert eff.ending_kind == kind
    assert eff.ending_off == off


def test_ret_n_penalty_scales(mona):
    small = mona.parseGadgetEffect(0x1000, " # pop eax # retn 0x08")
    big = mona.parseGadgetEffect(0x1000, " # pop eax # retn 0x40")
    assert small.score > big.score        # bigger N -> worse


# --- effect parsing table -------------------------------------------------

def test_mov_reg_reg_is_copy(mona):
    eff = mona.parseGadgetEffect(0x1000, " # mov ebx,eax # retn")
    assert eff.reg_writes["ebx"] == mona.SYM_COPY("eax")
    assert "eax" in eff.reg_reads


def test_mov_imm_is_value(mona):
    eff = mona.parseGadgetEffect(0x1000, " # mov eax,0x40 # retn")
    assert eff.reg_writes["eax"] == mona.SYM_VALUE(0x40)


def test_xor_self_zeroes(mona):
    eff = mona.parseGadgetEffect(0x1000, " # xor eax,eax # retn")
    assert eff.reg_writes["eax"] == mona.SYM_VALUE(0)


def test_xchg_swaps(mona):
    eff = mona.parseGadgetEffect(0x1000, " # xchg eax,ebx # retn")
    assert eff.reg_writes["eax"] == mona.SYM_COPY("ebx")
    assert eff.reg_writes["ebx"] == mona.SYM_COPY("eax")


def test_subreg_maps_to_parent(mona):
    eff = mona.parseGadgetEffect(0x1000, " # add al,0x5d # retn")
    assert "eax" in eff.clobbers        # al -> eax


def test_memory_write_counted(mona):
    eff = mona.parseGadgetEffect(0x1000, " # mov dword ptr [ecx],eax # retn")
    assert eff.mem_writes == 1
    assert "ecx" in eff.reg_reads
    assert "eax" in eff.reg_reads


def test_popad_writes_all_but_esp(mona):
    eff = mona.parseGadgetEffect(0x1000, " # popad # retn")
    for reg in ["eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"]:
        assert reg in eff.reg_writes
    assert "esp" not in eff.reg_writes


# --- stack_delta must equal getJunk (design invariant) --------------------

@pytest.mark.parametrize("chain", [
    " # pop eax # retn",
    " # pop eax # pop ebx # retn",
    " # add esp,0x7210 # retn",
    " # push eax # pop ebx # retn",
    " # popad # retn",
])
def test_stack_delta_matches_getjunk(mona, chain):
    eff = mona.parseGadgetEffect(0x1000, chain)
    assert eff.stack_delta == mona.getJunk(chain)


# --- reg->reg cost ordering: mov < xchg < push/pop ------------------------

def test_move_cost_ordering(mona):
    mov = mona.getGadgetEffect(0x1, " # mov ebx,eax # retn")
    xchg = mona.getGadgetEffect(0x2, " # xchg eax,ebx # retn")
    pushpop = mona.getGadgetEffect(0x3, " # push eax # pop ebx # retn")
    cmov = mona.gadgetCost(mov)
    cxchg = mona.gadgetCost(xchg)
    cpp = mona.gadgetCost(pushpop)
    assert cmov < cxchg < cpp


# --- getBestGadget: deterministic argmax ----------------------------------

def test_get_best_gadget_picks_cleanest(mona):
    pool = {
        0xAAAA: " # pop eax # add esp,0x7210 # retn 0x08",
        0xBBBB: " # pop eax # retn",                 # cleanest
        0xCCCC: " # xor eax,ecx # pop eax # retn 0x04",
    }
    assert mona.getBestGadget(pool) == 0xBBBB
    # deterministic across repeated calls
    assert mona.getBestGadget(pool) == 0xBBBB


# --- bad-char soft-exclude ------------------------------------------------

def test_badchar_soft_excludes(mona):
    # 0x10001100 contains byte 0x00 -> flagged when 0x00 is a bad char
    eff = mona.parseGadgetEffect(0x10001100, " # pop eax # retn", badchars=b"\x00")
    assert 0x00 in eff.addr_badchars
    assert eff.score < 0        # -1000 soft-exclude dominates

    clean = mona.parseGadgetEffect(0x10111213, " # pop eax # retn", badchars=b"\x00")
    assert clean.addr_badchars == []
    assert mona.getBestGadget(
        {0x10001100: " # pop eax # retn", 0x10111213: " # pop eax # retn"},
        badchars=b"\x00",
    ) == 0x10111213
