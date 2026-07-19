"""P3 unit tests: register-state transfer search (Dijkstra move-planner).

Debugger-free. Exercises buildMoveGraph, cheapestRegPath, the optimized
getShortestGadget delegation, and getGadgetMoveRegToReg under the opt context.
"""
import pytest


@pytest.fixture
def opt_ctx(mona):
    """Enable the optimized selection context for a test, then reset it."""
    mona._rop_opt_ctx = {"badset": set(), "strictbad": False}
    yield mona
    mona._rop_opt_ctx = None


# --- getShortestGadget delegation: mov < xchg < push/pop ------------------

def test_selection_prefers_mov_over_xchg_over_pushpop(opt_ctx):
    m = opt_ctx
    # three ways to realize eax->ebx, as a single suggestion pool
    pool = {
        0x1: " # mov ebx,eax # retn",       # cleanest
        0x2: " # xchg eax,ebx # retn",
        0x3: " # push eax # pop ebx # retn",
    }
    assert m.getShortestGadget(pool) == 0x1
    # cost ordering underpinning the choice
    cmov = m.gadgetCost(m.getGadgetEffect(0x1, pool[0x1]))
    cxchg = m.gadgetCost(m.getGadgetEffect(0x2, pool[0x2]))
    cpp = m.gadgetCost(m.getGadgetEffect(0x3, pool[0x3]))
    assert cmov < cxchg < cpp


def test_selection_avoids_badaddr(opt_ctx):
    m = opt_ctx
    m._rop_opt_ctx = {"badset": {0x00}, "strictbad": False}
    pool = {
        0x10001100: " # pop eax # retn",   # addr has 0x00 -> penalized
        0x10111213: " # pop eax # retn",   # clean addr
    }
    assert m.getShortestGadget(pool) == 0x10111213


# --- buildMoveGraph -------------------------------------------------------

def test_build_move_graph(mona):
    sugg = {
        "move eax -> ebx": {0x101: " # mov ebx,eax # retn"},
        "move ecx -> ebx": {0x103: " # mov ebx,ecx # retn"},
        "pop eax": {0x900: " # pop eax # retn"},   # ignored (not a move)
    }
    edges = mona.buildMoveGraph(sugg, sugg)
    assert set(edges.keys()) == {("eax", "ebx"), ("ecx", "ebx")}
    assert edges[("eax", "ebx")][1] == 0x101


def test_build_move_graph_picks_cheapest_gadget(mona):
    sugg = {
        "move eax -> ebx": {
            0x1: " # mov ebx,eax # add esp,0x100 # retn 0x08",  # dirty
            0x2: " # mov ebx,eax # retn",                        # clean
        },
    }
    edges = mona.buildMoveGraph(sugg, sugg)
    assert edges[("eax", "ebx")][1] == 0x2


# --- cheapestRegPath (Dijkstra) -------------------------------------------

def test_direct_edge_when_cheapest(mona):
    edges = {
        ("eax", "ebx"): (80, 0x1),
        ("eax", "ecx"): (80, 0x2),
        ("ecx", "ebx"): (80, 0x3),
    }
    assert mona.cheapestRegPath(edges, "eax", "ebx") == ["eax", "ebx"]


def test_cheaper_two_hop_beats_expensive_direct(mona):
    edges = {
        ("eax", "ebx"): (500, 0x1),   # expensive direct
        ("eax", "ecx"): (10, 0x2),
        ("ecx", "ebx"): (10, 0x3),
    }
    assert mona.cheapestRegPath(edges, "eax", "ebx") == ["eax", "ecx", "ebx"]


def test_unreachable_returns_none(mona):
    edges = {("eax", "ebx"): (80, 0x1)}
    assert mona.cheapestRegPath(edges, "eax", "edi") is None


def test_same_reg_is_trivial(mona):
    assert mona.cheapestRegPath({}, "eax", "eax") == ["eax"]


# --- getGadgetMoveRegToReg under opt context ------------------------------

def test_move_direct_single_hop(opt_ctx):
    m = opt_ctx
    sugg = {"move eax -> ebx": {0x101: " # mov ebx,eax # retn"}}
    ig = {0x101: " # mov ebx,eax # retn"}   # interestinggadgets is flat: ptr->instr
    chain = m.getGadgetMoveRegToReg("eax", "ebx", sugg, ig)
    assert len(chain) == 1
    assert chain[0][0] == 0x101


def test_move_multi_hop(opt_ctx):
    m = opt_ctx
    sugg = {
        "move eax -> ecx": {0x102: " # mov ecx,eax # retn"},
        "move ecx -> ebx": {0x103: " # mov ebx,ecx # retn"},
    }
    ig = {0x102: " # mov ecx,eax # retn", 0x103: " # mov ebx,ecx # retn"}
    chain = m.getGadgetMoveRegToReg("eax", "ebx", sugg, ig)
    assert [c[0] for c in chain] == [0x102, 0x103]


def test_move_falls_back_when_no_path(opt_ctx):
    m = opt_ctx
    # no move suggestion at all -> opt planner returns None -> legacy edge
    # builder also finds nothing -> empty chain (not a crash)
    chain = m.getGadgetMoveRegToReg("eax", "ebx", {}, {})
    assert chain == []


def test_legacy_path_untouched_when_ctx_off(mona):
    mona._rop_opt_ctx = None
    sugg = {"move eax -> ebx": {0x101: " # mov ebx,eax # retn"}}
    ig = {0x101: " # mov ebx,eax # retn"}
    chain = mona.getGadgetMoveRegToReg("eax", "ebx", sugg, ig)
    # legacy single-edge builder still returns the gadget
    assert chain[0][0] == 0x101
