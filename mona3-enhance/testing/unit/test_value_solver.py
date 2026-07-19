"""P6 unit tests: value-construction solver."""
import pytest

BADSET = {0x00, 0x0a, 0x0d, 0x25, 0x26, 0x3d}


# --- isCleanValue ---------------------------------------------------------

@pytest.mark.parametrize("v,clean", [
    (0xfffffdff, True),    # ff fd ff ff
    (0x00000201, False),   # has nulls
    (0x00001000, False),   # has nulls
    (0x11223344, True),
    (0x11223d44, False),   # has 0x3d
    (0x01011101, True),
])
def test_is_clean_value(mona, v, clean):
    assert mona.isCleanValue(v, BADSET) is clean


def test_clean_value_no_badset(mona):
    assert mona.isCleanValue(0x00000000, None) is True


# --- deriveValueCaps ------------------------------------------------------

def test_derive_caps(mona):
    sugg = {
        "pop eax": {}, "pop ebx": {}, "neg eax": {},
        "add value to eax": {}, "inc ecx": {}, "dec edx": {},
        "move eax -> ebx": {},   # ignored
    }
    caps = mona.deriveValueCaps(sugg)
    assert caps["pop"] == {"eax", "ebx"}
    assert caps["neg"] == {"eax"}
    assert caps["addval"] == {"eax"}
    assert caps["inc"] == {"ecx"}
    assert caps["dec"] == {"edx"}


# --- solveValueToReg ------------------------------------------------------

def test_direct_pop_when_clean(mona):
    caps = {"pop": {"eax"}, "neg": set(), "addval": set(), "inc": set(), "dec": set()}
    sol = mona.solveValueToReg("eax", 0x11223344, caps, BADSET)
    assert sol is not None
    cost, plan = sol
    assert plan == [("pop", "eax", 0x11223344)]   # cheapest: single clean pop


def test_negate_when_value_has_badchars(mona):
    caps = {"pop": {"eax"}, "neg": {"eax"}, "addval": set(), "inc": set(), "dec": set()}
    sol = mona.solveValueToReg("eax", 0x201, caps, BADSET)  # 0x201 has nulls
    cost, plan = sol
    assert plan[0] == ("pop", "eax", 0xfffffdff)   # -0x201, clean
    assert plan[1] == ("neg", "eax")


def test_neg_then_dec_for_0x1000(mona):
    # 0x1000 has nulls AND negate(0x1000)=0xfffff000 has a null -> plain neg blocked.
    # solver must use neg-then-adjust: pop 0xffffefff; neg -> 0x1001; dec -> 0x1000.
    caps = {"pop": {"eax"}, "neg": {"eax"}, "addval": set(), "inc": {"eax"}, "dec": {"eax"}}
    sol = mona.solveValueToReg("eax", 0x1000, caps, BADSET)
    assert sol is not None
    cost, plan = sol
    assert plan[0] == ("pop", "eax", 0xffffefff)
    assert plan[1] == ("neg", "eax")
    assert plan[2] == ("dec", "eax")
    assert mona.isCleanValue(plan[0][2], BADSET)


def test_inc_adjust_without_neg(mona):
    # value 0x1122330a: low byte 0x0a is bad, high bytes clean.
    # pop 0x11223309 (clean) ; inc -> 0x1122330a. No neg needed.
    caps = {"pop": {"eax"}, "neg": set(), "addval": set(), "inc": {"eax"}, "dec": set()}
    sol = mona.solveValueToReg("eax", 0x1122330a, caps, BADSET)
    assert sol is not None
    _c, plan = sol
    assert plan[0] == ("pop", "eax", 0x11223309)
    assert plan[-1] == ("inc", "eax")
    assert mona.isCleanValue(plan[0][2], BADSET)


def test_none_when_reg_lacks_primitives(mona):
    # ebx can only be popped; 0x201 not directly poppable (nulls), no neg/inc/dec
    caps = {"pop": {"ebx"}, "neg": {"eax"}, "addval": {"eax"}, "inc": set(), "dec": set()}
    assert mona.solveValueToReg("ebx", 0x201, caps, BADSET) is None


def test_none_when_no_pop(mona):
    caps = {"pop": set(), "neg": {"eax"}, "addval": {"eax"}, "inc": {"eax"}, "dec": {"eax"}}
    assert mona.solveValueToReg("eax", 0x11223344, caps, BADSET) is None


def test_direct_beats_negate_on_cost(mona):
    # a clean value: direct pop (80) must win over any multi-op construction
    caps = {"pop": {"eax"}, "neg": {"eax"}, "addval": set(), "inc": {"eax"}, "dec": {"eax"}}
    cost, plan = mona.solveValueToReg("eax", 0x11223344, caps, BADSET)
    assert len(plan) == 1
    assert cost == mona._VC_COST["pop"]


# --- emit: putValueInRegOpt -> putchain ------------------------------------

def test_emit_putchain_for_0x1000(mona):
    sugg = {
        "pop eax": {0x1002f729: " # pop eax # retn"},
        "neg eax": {0x1005a3e6: " # neg eax # retn"},
        "dec eax": {0x1001181d: " # dec eax # retn"},
    }
    ig = {0x1002f729: " # pop eax # retn", 0x1005a3e6: " # neg eax # retn",
          0x1001181d: " # dec eax # retn"}
    mona._rop_opt_ctx = {"badset": BADSET, "strictbad": False}
    try:
        crit = {"badchars": bytes(sorted(BADSET))}
        pc = mona.putValueInRegOpt("eax", 0x1000, "flAllocationType", sugg, ig, crit)
    finally:
        mona._rop_opt_ctx = None
    assert pc is not None
    # pop gadget, the negate value (with freetext), neg gadget, dec gadget
    assert pc[0][0] == 0x1002f729
    assert pc[1] == [0xffffefff, "flAllocationType", 0]
    assert pc[2][0] == 0x1005a3e6
    assert pc[3][0] == 0x1001181d


def test_emit_returns_none_when_gadget_missing(mona):
    # solver wants neg but no neg gadget present -> None (legacy fallback)
    sugg = {"pop eax": {0x1: " # pop eax # retn"}}
    ig = {0x1: " # pop eax # retn"}
    mona._rop_opt_ctx = {"badset": BADSET, "strictbad": False}
    try:
        crit = {"badchars": bytes(sorted(BADSET))}
        # 0x201 needs neg (blocked: no neg gadget) -> None
        assert mona.putValueInRegOpt("eax", 0x201, "dwSize", sugg, ig, crit) is None
    finally:
        mona._rop_opt_ctx = None


# --- P7: cross-register value + move --------------------------------------

@pytest.fixture
def _opt(mona):
    mona._rop_opt_ctx = {"badset": BADSET, "strictbad": False}
    yield mona
    mona._rop_opt_ctx = None


def test_via_source_builds_in_eax_then_moves(_opt):
    m = _opt
    # ebx target 0x201: ebx has no neg -> must build in eax then move.
    sugg = {
        "pop eax": {0x1000: " # pop eax # retn"},
        "neg eax": {0x1001: " # neg eax # retn"},
        "pop ebx": {0x1002: " # pop ebx # retn"},   # can't build 0x201 (nulls) directly
        "move eax -> ebx": {0x1003: " # mov ebx,eax # retn"},
    }
    ig = {0x1000: " # pop eax # retn", 0x1001: " # neg eax # retn",
          0x1002: " # pop ebx # retn", 0x1003: " # mov ebx,eax # retn"}
    crit = {"badchars": bytes(sorted(BADSET)), "accesslevel": "*"}
    chain = m.putValueViaSourceOpt("ebx", 0x201, "dwSize", sugg, ig, crit)
    assert chain is not None
    ptrs = [e[0] for e in chain]
    assert 0x1000 in ptrs and 0x1001 in ptrs   # pop eax + neg eax (build in eax)
    assert 0x1003 in ptrs                        # move eax -> ebx
    assert [0xfffffdff, "dwSize (built in eax)", 0] in chain


def test_via_source_picks_cheaper_move(_opt):
    m = _opt
    # clean value buildable by direct pop in eax OR ecx. move ecx->ebx is a
    # clean 1-instr; move eax->ebx is dirty -> via-source must pick the ecx route.
    sugg = {
        "pop eax": {0x1000: " # pop eax # retn"},
        "pop ecx": {0x1010: " # pop ecx # retn"},
        "move eax -> ebx": {0x1030: " # push eax # pop ebx # add esp,0x400 # retn 0x08"},
        "move ecx -> ebx": {0x1040: " # mov ebx,ecx # retn"},
    }
    ig = {0x1000: " # pop eax # retn", 0x1010: " # pop ecx # retn",
          0x1030: " # push eax # pop ebx # add esp,0x400 # retn 0x08",
          0x1040: " # mov ebx,ecx # retn"}
    crit = {"badchars": bytes(sorted(BADSET)), "accesslevel": "*"}
    chain = m.putValueViaSourceOpt("ebx", 0x11223344, "v", sugg, ig, crit)
    assert chain is not None
    ptrs = [e[0] for e in chain]
    assert 0x1040 in ptrs        # cheap ecx->ebx move chosen
    assert 0x1030 not in ptrs    # dirty eax->ebx move avoided


def test_via_source_none_when_no_move(_opt):
    m = _opt
    sugg = {"pop eax": {0x1000: " # pop eax # retn"},
            "neg eax": {0x1001: " # neg eax # retn"},
            "pop ebx": {0x1002: " # pop ebx # retn"}}   # no move eax->ebx
    ig = {0x1000: " # pop eax # retn", 0x1001: " # neg eax # retn", 0x1002: " # pop ebx # retn"}
    crit = {"badchars": bytes(sorted(BADSET)), "accesslevel": "*"}
    assert m.putValueViaSourceOpt("ebx", 0x201, "v", sugg, ig, crit) is None


# --- flexible value (nextCleanValue) --------------------------------------

def _clean(v, b):
    return all(((v >> (8 * i)) & 0xff) not in b for i in range(4))


@pytest.mark.parametrize("v", [0x201, 0x1000, 0x40, 0x1, 0x3d0000])
def test_next_clean_value_with_null_bad(mona, v):
    r = mona.nextCleanValue(v, BADSET)         # BADSET includes 0x00
    assert r is not None
    assert r >= v                               # flexible: >= minimum
    assert _clean(r, BADSET)                    # and bad-char-free


def test_next_clean_keeps_exact_when_null_not_bad(mona):
    # 0x00 NOT a bad char -> 0x201 is already valid, must be kept unchanged
    nonull = {0x0a, 0x0d, 0x25, 0x26, 0x3d}
    assert mona.nextCleanValue(0x201, nonull) == 0x201
    assert mona.nextCleanValue(0x1000, nonull) == 0x1000


def test_next_clean_keeps_already_clean(mona):
    assert mona.nextCleanValue(0x11223344, BADSET) == 0x11223344


def test_next_clean_none_when_no_allowed(mona):
    allbad = set(range(256))
    assert mona.nextCleanValue(0x201, allbad) is None


def test_flexible_reg_registry(mona):
    assert mona._flexibleRegs("virtualprotect") == {"ebx"}
    assert mona._flexibleRegs("virtualalloc") == {"ebx"}
    assert mona._flexibleRegs("setprocessdeppolicy") == set()
    assert mona._flexibleName("virtualprotect", "ebx") == "dwSize"


# --- report ---------------------------------------------------------------

def test_value_report_marks_needs_move(mona):
    sugg = {"pop eax": {}, "pop ebx": {}, "neg eax": {}}
    rep = mona.buildValueConstructionReport(sugg, BADSET)
    assert "Value construction advisor" in rep
    assert "(none)" in rep       # ebx cannot build 0x201
    assert "neg eax" in rep
