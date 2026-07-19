"""Emit smoke test: drive the REAL createRopChains headless.

Monkeypatches the debugger-facing collaborators (MnPointer/MnModule/MnLog/
IAT + jmp lookups) with faithful fakes, then runs createRopChains for the
VirtualAlloc recipe under -optimize with a gadget pool crafted so every
register resolves through the value solver. Verifies the Python + XML emit
assemble correctly and carry the solver's constructions (e.g. ebx via inc,
edx via neg+dec) instead of an expensive move.

This exercises the imperative emit glue that the pure-engine tests can't reach.
"""
import pytest

BAD = {0x00, 0x0a, 0x0d, 0x25, 0x26, 0x3d}

# clean gadget addresses (no byte in BAD), all inside the fake module range
G = {
    0x10111111: " # pop eax # retn",
    0x10111213: " # pop ebx # retn",
    0x10111415: " # pop ecx # retn",
    0x10111617: " # pop edx # retn",
    0x10111819: " # pop ebp # retn",
    0x1011181b: " # pop edi # retn",
    0x10111c1f: " # inc ebx # retn",
    0x10111e21: " # neg ecx # retn",
    0x10112223: " # neg edx # retn",
    0x10112427: " # dec edx # retn",
    0x10112829: " # pushad # retn",
}
SUGG = {
    "pop eax": {0x10111111: G[0x10111111]},
    "pop ebx": {0x10111213: G[0x10111213]},
    "pop ecx": {0x10111415: G[0x10111415]},
    "pop edx": {0x10111617: G[0x10111617]},
    "pop ebp": {0x10111819: G[0x10111819]},
    "pop edi": {0x1011181b: G[0x1011181b]},
    "inc ebx": {0x10111c1f: G[0x10111c1f]},
    "neg ecx": {0x10111e21: G[0x10111e21]},
    "neg edx": {0x10112223: G[0x10112223]},
    "dec edx": {0x10112427: G[0x10112427]},
    "pushad": {0x10112829: G[0x10112829]},
}


@pytest.fixture
def emit_env(mona):
    """Install faithful fakes for the debugger collaborators; restore after."""
    saved = {name: getattr(mona, name) for name in
             ("MnPointer", "MnModule", "getGadgetAddressInfo", "getModulesToQuery",
              "getRopFuncPtr", "getPickupGadget", "findJMP", "getAPointer", "MnLog")}
    writes = []

    real_ptr = mona.MnPointer

    class FakePtr:
        def __init__(self, addr):
            self.addr = addr & 0xffffffff
        def belongsTo(self):
            return "fakemod" if 0x10000000 <= self.addr < 0x10120000 else ""
        def getAddress(self):
            return self.addr
        def __str__(self):
            return ""
    # keep the real byte-range class attrs so _addressMeetsCriteria still works
    for a in ("_NullRange", "_AsciiRange", "_AsciiPrintRange", "_AsciiUpperRange",
              "_AsciiLowerRange", "_AsciiAlphaRange", "_AsciiNumericRange", "_AsciiSpaceRange"):
        setattr(FakePtr, a, getattr(real_ptr, a))

    class FakeModule:
        def __init__(self, name="fakemod"):
            self.moduleBase = 0x10000000
            self.moduleVersion = "1.0.0"
            self.isSafeSEH = False
        def __str__(self):
            return "fakemod"

    class FakeLog:
        def __init__(self, name):
            self.name = name
        def reset(self, **k):
            return self.name
        def write(self, content, f):
            writes.append((self.name, content))

    mona.MnPointer = FakePtr
    mona.MnModule = FakeModule
    mona.getGadgetAddressInfo = lambda p: ""
    mona.getModulesToQuery = lambda mc: ["fakemod"]
    mona.getRopFuncPtr = lambda *a, **k: (0x10001000, "ptr to VirtualAlloc()")
    mona.getPickupGadget = lambda reg, val, ft, *a, **k: ([[0x10111111, "ptr to VirtualAlloc() [fakemod]", 0]], [])
    mona.findJMP = lambda *a, **k: {"jmp esp": [0x10113111]}
    mona.getAPointer = lambda *a, **k: 0x10114151
    mona.MnLog = FakeLog

    try:
        yield mona, writes
    finally:
        for name, val in saved.items():
            setattr(mona, name, val)


class _Progress:
    def write(self, *a, **k):
        pass


def test_virtualalloc_emit_end_to_end(emit_env):
    mona, writes = emit_env
    criteria = {"badchars": bytes(sorted(BAD)), "accesslevel": "*"}
    modulecriteria = {"aslr": False, "rebase": False, "os": False}

    vplog = mona.createRopChains(
        dict(SUGG), dict(G), dict(G), modulecriteria, criteria,
        _Progress(), "prog", "virtualalloc", True, 3, False, {})

    # markdown / code emit
    assert "*** [ Python ] ***" in vplog
    assert "create_rop_chain" in vplog
    # ebx (dwSize=0x1) uses the flexible bad-char-free value (direct pop)
    assert "flexible dwSize" in vplog
    assert "0x01010101" in vplog
    # edx (flAllocationType=0x1000) is an EXACT flag -> still constructed
    assert "neg edx" in vplog and "dec edx" in vplog
    assert "add esp,7210" not in vplog                 # no monster gadget
    # P5/P6 reports appended under -optimize
    assert "Module ranking" in vplog
    assert "Value construction advisor" in vplog

    # XML emit
    xmls = [c for n, c in writes if "<rop>" in c]
    assert len(xmls) == 1
    xml = xmls[0]
    assert xml.strip().startswith("<?xml")
    assert "</db>" in xml
    assert xml.count("<gadget") >= 15
    # flexible dwSize rendered as a literal value, and edx still constructed
    assert 'value="0x01010101"' in xml
    assert "neg edx # retn" in xml and "dec edx # retn" in xml


def test_virtualprotect_flexible_dwsize_kills_monster(emit_env):
    mona, writes = emit_env
    criteria = {"badchars": bytes(sorted(BAD)), "accesslevel": "*"}   # 0x00 is bad
    modulecriteria = {"aslr": False, "rebase": False, "os": False}
    # VirtualProtect pool: ebx has ONLY pop (no neg/inc/dec/move) -> without the
    # flexible-value substitution, ebx=0x201 would need an expensive move.
    sugg = {
        "pop eax": {0x10111111: " # pop eax # retn"},
        "pop ebx": {0x10111213: " # pop ebx # retn"},
        "pop ecx": {0x10111415: " # pop ecx # retn"},
        "pop edx": {0x10111617: " # pop edx # retn"},
        "pop ebp": {0x10111819: " # pop ebp # retn"},
        "pop edi": {0x1011181b: " # pop edi # retn"},
        "neg edx": {0x10112223: " # neg edx # retn"},
        "pushad": {0x10112829: " # pushad # retn"},
    }
    ig = {p: v for d in sugg.values() for p, v in d.items()}
    vplog = mona.createRopChains(dict(sugg), dict(ig), dict(ig), modulecriteria,
                                 criteria, _Progress(), "prog", "virtualprotect",
                                 True, 3, False, {})
    # ebx (dwSize=0x201) built as a direct pop of a bad-char-free flexible value
    assert "flexible dwSize" in vplog
    assert "0x01010101" in vplog
    # no expensive move / monster gadget was needed for ebx
    assert "add esp,7210" not in vplog
    # edx (NewProtect=0x40) is an EXACT flag -> NOT substituted, still constructed
    assert "neg edx" in vplog


def test_emit_context_cleared_after_run(emit_env):
    mona, writes = emit_env
    criteria = {"badchars": bytes(sorted(BAD)), "accesslevel": "*"}
    modulecriteria = {"aslr": False, "rebase": False, "os": False}
    mona.createRopChains(dict(SUGG), dict(G), dict(G), modulecriteria, criteria,
                         _Progress(), "prog", "virtualalloc", True, 3, False, {})
    # optimized context must be reset so later legacy runs are unaffected
    assert mona._rop_opt_ctx is None
