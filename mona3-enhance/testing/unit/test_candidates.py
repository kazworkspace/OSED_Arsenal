"""P4 unit tests: Yen k-shortest register routes + candidate report."""
import pytest


# --- kCheapestRegPaths (Yen) ----------------------------------------------

def test_yen_returns_ordered_distinct_paths(mona):
    edges = {
        ("eax", "ebx"): (100, 0x1),
        ("eax", "ecx"): (10, 0x2),
        ("ecx", "ebx"): (10, 0x3),
        ("eax", "edx"): (20, 0x4),
        ("edx", "ebx"): (20, 0x5),
    }
    paths = mona.kCheapestRegPaths(edges, "eax", "ebx", k=3)
    costs = [c for c, _ in paths]
    routes = [p for _, p in paths]
    assert costs == sorted(costs)                 # ordered by cost
    assert costs[0] == 20                          # eax->ecx->ebx cheapest
    assert routes[0] == ["eax", "ecx", "ebx"]
    assert len(set(tuple(r) for r in routes)) == len(routes)   # distinct


def test_yen_k_limit(mona):
    edges = {
        ("eax", "ecx"): (10, 0x2), ("ecx", "ebx"): (10, 0x3),
        ("eax", "edx"): (20, 0x4), ("edx", "ebx"): (20, 0x5),
        ("eax", "ebx"): (100, 0x1),
    }
    assert len(mona.kCheapestRegPaths(edges, "eax", "ebx", k=2)) == 2


def test_yen_single_route(mona):
    edges = {("eax", "ebx"): (80, 0x1)}
    paths = mona.kCheapestRegPaths(edges, "eax", "ebx", k=5)
    assert paths == [(80, ["eax", "ebx"])]


def test_yen_unreachable(mona):
    assert mona.kCheapestRegPaths({("eax", "ebx"): (80, 0x1)}, "eax", "edi", k=3) == []


# --- buildRegisterCandidateReport -----------------------------------------

def test_report_lists_ranked_candidates(mona):
    sugg = {
        "move eax -> ecx": {0x100baecb: " # xchg eax,ecx # retn"},
        "move ecx -> ebx": {0x100c0000: " # mov ebx,ecx # retn"},
        "move eax -> ebx": {
            0x100639e1: " # push eax # add al,0x5d # mov eax,0x1 # pop ebx # add esp,0x7210 # retn 0x08",
        },
    }
    rep = mona.buildRegisterCandidateReport(sugg, {}, badset=set(), k=3, goals=["ebx"])
    assert "Ranked register-transfer candidates" in rep
    assert "### eax -> ebx" in rep
    # both the direct (monster) route and the 2-hop clean route appear
    assert "Candidate 1" in rep and "Candidate 2" in rep
    # the huge stack adjust is flagged
    assert "filler=29200" in rep


def test_report_flags_badaddr(mona):
    sugg = {"move eax -> ebx": {0x10002500: " # mov ebx,eax # retn"}}  # 0x25 in addr
    rep = mona.buildRegisterCandidateReport(sugg, {}, badset={0x25}, k=3, goals=["ebx"])
    assert "bad-addr byte" in rep


def test_report_handles_no_route(mona):
    rep = mona.buildRegisterCandidateReport({}, {}, badset=set(), k=3, goals=["ebx"])
    assert "no register-move route" in rep
