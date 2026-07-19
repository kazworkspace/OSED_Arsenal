# Mona ROP Generator Upgrade — Engineering Design

**Target:** `mona.py` v3.0.3025 (Python 3.10), x86 (32-bit) auto-generator only.
**Constraints (locked):** 32-bit only · optimized path flag-gated, legacy stays default · ranked candidates appended to `rop.md` · this doc reviewed before any code change.

---

## 0. Scope

Improve quality of auto-generated ROP chains (VirtualProtect / VirtualAlloc recipes in `createRopChains`) via:
gadget quality scoring, register-state-aware search, cost-based chain optimization, multiple ranked candidates, bad-char tradeoff, module ranking. No behavior change unless the user opts in with new flags. 64-bit and JOP untouched.

---

## 1. Baseline (as-built, with line refs)

| Stage | Function | Line | Key data |
|---|---|---|---|
| Command entry | `procROP` | 33461 | parses args → `findROPGADGETS` (33539) |
| Discovery | `findROPGADGETS` | 25624 | builds `ropgadgets`, `interestinggadgets`, `stackpivots` |
| Instruction filter | `isGoodGadgetInstr` / `isInterestingGadget` | 30963 / 30716 | keep/drop gadget |
| Addr bad-char filter | `isGoodGadgetPtr`→`meetsCriteria` | 30887 | **discards** bad-addr gadget (25944) |
| Classify | `getRopSuggestion` / `suggestedGadgetCheck` | 31007 / 31394 | `suggestions[semantic] -> {ptr:instr}` |
| **Select ("ranking")** | `getShortestGadget` | 30691 | `#`-count, tie len, `random.choice` |
| Build chain | `createRopChains` | 29080 | hardcoded reg recipes, per-reg independent |
| Reg helpers | `getPickupGadget`/`getGadgetValueToReg`/`getGadgetMoveRegToReg`/`clearReg` | 29828/30566/30499/30523 | |
| Stack accounting | `getJunk` | 30649 | pop/push/`add esp` → filler bytes |

**Core data shapes**
```
ropgadgets:          dict[startptr:int]  -> fullchain:str   # " # pop eax # retn"
interestinggadgets:  dict[startptr:int]  -> fullchain:str
suggestions:         dict[semantic:str]  -> dict[ptr:int -> instr:str]
                     # semantic keys: "pop eax", "move eax -> ebx", "clear eax",
                     #                "add value to ecx", "neg eax", "pushad", ...
stackpivots:         dict[distance:int]  -> [[ptr, chain], ...]
```

**Baseline limitations (what we fix)**
1. Only quality signal = instruction count; `random.choice` makes output non-deterministic (30698).
2. `ret N`, large `add esp`, memory writes, extra reg clobbers — not penalized.
3. No register-state model; recipe steps chosen independently (`skiplist`/`replacelist` are the only cross-step glue).
4. One chain emitted; no alternatives.
5. Bad-addr gadgets discarded at discovery — clean-gadget/bad-addr tradeoff impossible.
6. Modules processed in enumeration order; no ranking.

---

## 2. Design overview

Additive layer. New module-scoped classes + functions, no edits to existing selection logic on the default path. A single flag `-optimize` swaps `getShortestGadget`-based selection for the cost-search engine inside `createRopChains`; `-candidates N` emits N ranked chains.

```
discovery ──> ropgadgets ──┬─> [legacy] getRopSuggestion + getShortestGadget  (default)
                           └─> [opt]    GadgetEffect cache ─> StateSearch ─> Candidates ─> rop.md append
```

---

## 3. New components

### 3.1 `GadgetEffect` — structured gadget semantics

```python
class GadgetEffect:
    __slots__ = ("ptr","instrs","reg_writes","reg_reads","clobbers",
                 "mem_writes","stack_delta","ending_kind","ending_off",
                 "score","addr_badchars")
    # reg_writes:  dict[str -> Sym]      postconditions
    # reg_reads:   set[str]
    # clobbers:    set[str]              regs written that the step did not intend
    # mem_writes:  int                   count of "mov [reg],..","push [.." style writes
    # stack_delta: int                   == getJunk(fullchain) (reuse, do NOT reinvent)
    # ending_kind: "ret" | "retn" | "other"
    # ending_off:  int                   N for "retn 0xNN", else 0
    # score:       int                   from scoreGadget()
    # addr_badchars: list[int]           bad bytes present in ptr; [] == clean addr
```

`Sym` (symbolic register value), hashable:
```python
UNKNOWN            # ("u",)
VALUE(x)           # ("v", x)
COPY_OF(reg0)      # ("c", "eax")   value originally in reg0 at chain start
STACK              # ("s",)         current esp-derived
```

**Parser** `parseGadgetEffect(ptr, fullchain) -> GadgetEffect`. Reuses the existing `fullchain.split("#")` convention. Regex-free where possible (mirror `getJunk` string parsing). Handles the instruction vocabulary already whitelisted by `isInterestingGadget` (30719): `pop/push/mov/xchg/lea/xor/and/or/add/sub/adc/inc/dec/neg/popad/pushad/nop/clc/cld/test`. Anything unrecognized → mark reg as `UNKNOWN` clobber (conservative, never claims false control).

### 3.2 `scoreGadget(effect) -> int`

```python
def scoreGadget(e):
    s = 100
    s -= 8 * max(0, len(e.instrs) - 1)          # extra instructions
    if e.ending_kind == "retn":
        s -= 40
        s -= min(30, e.ending_off // 4)         # bigger ret N worse
    elif e.ending_kind == "other":
        s -= 60                                  # jmp/call ending, risky
    s -= 25 * e.mem_writes
    s -= 15 * len(e.clobbers)
    if abs(e.stack_delta) > 0x40:
        s -= 30                                  # in-gadget stack shift
    if len(e.instrs) == 1 and e.ending_kind == "ret":
        s += 20                                  # single-purpose + clean ret
    if e.addr_badchars:
        s -= 1000                                # soft-exclude (see 3.5)
    return s
```

Anchored assertion (becomes a unit test): `pop eax # ret` ⇒ ~112; `push eax # add al,5d # mov eax,1 # pop ebx # add esp,7210h # retn 8` ⇒ strongly negative. Good ranks above bad by construction.

`getBestGadget(cands, effects) -> ptr` = argmax score; tie-break: fewer instrs, then shorter string (preserves old tie logic), **deterministic** (no `random.choice`). Legacy `getShortestGadget` kept untouched for default path.

### 3.3 Register-state search (cost-based, objectives 2+3)

State `= tuple(sorted (reg, Sym))` over the ≤7 goal-relevant regs of the active recipe. Each usable suggestion gadget = a transition:

```python
class Transition:
    ptr:int; effect:GadgetEffect
    def apply(state)-> new_state | None   # None if precondition unmet
    cost = 200 - effect.score             # low score = high cost; always >0
```

Search = **Dijkstra** (uniform-cost) from start state to any state satisfying the recipe goal; A\* heuristic `h = 8 * (#unsatisfied goal regs)` (admissible: each reg needs ≥1 gadget). Clobber = transition that also sets non-target regs to `UNKNOWN`, raising cost of later re-satisfying them → search naturally avoids destroying finished registers. `EAX→EBX` outcome: `mov ebx,eax` (cost≈88) < `xchg` (≈90) < `push eax;pop ebx` (≈112) — matches your spec without special-casing.

Guardrails: cap explored nodes (e.g. 20000); on cap-hit fall back to legacy greedy for that register and log it. Only goal-relevant regs tracked → state space bounded.

### 3.4 Multiple candidates (objective 4)

`kShortestChains(graph, start, goal, k) ` = **Yen's algorithm** over the transition graph (k × Dijkstra). Rank results by tuple:
```
(all_regs_satisfied desc, total_score desc, gadget_count asc,
 total_stack_filler asc, num_badaddr asc)
```
Default `k=3` (flag `-candidates N`, clamp 1..10). Output section appended to `rop.md` (see 3.6).

### 3.5 Bad-char tradeoff (objective 5)

Stop discarding at discovery **only when `-optimize` set**. Change: in `findROPGADGETS`, when `isGoodGadgetPtr` fails *solely* on bad-char criteria, still store the gadget but tag `addr_badchars`. Score applies −1000 (soft-exclude): a bad-addr gadget is chosen only if no clean gadget accomplishes the step, and the candidate list surfaces the tradeoff explicitly ("Candidate 2 uses cleaner gadget but addr byte 0x00"). Strict mode (`-optimize -strictbad`) restores hard exclusion. Default path behavior unchanged.

### 3.6 Module ranking (objective 6)

`scoreModule(module, effects_in_module) -> int`:
```
+ count(clean "pop r32 # ret")              distinct regs covered
+ 5 * distinct regs with a cost<100 controller
+ 15 if IAT ptr to target API present (reuse getRopFuncPtr signal)
+ (fraction of gadgets with clean addr) * 20
- 10 if ASLR/rebase (already filtered, defensive)
```
`createRopChains` iterates modules high-score-first. Pure ordering change; does not exclude modules.

### 3.7 Output format

`rop.md` unchanged sections preserved. Append, under a new heading, per routine:
```
## Ranked ROP candidates for VirtualProtect() [optimized]
### Candidate 1 — score 95 · 24 gadgets · 0 stack-comp · 0 bad-addr
  <ruby/python/c block, same emitter as legacy>
### Candidate 2 — score 80 · 30 gadgets · 2 stack-adj · 1 bad-addr(0x00 in ptr)
  ...
```
Legacy single-chain block still emitted above it → zero regression for existing parsers.

---

## 4. Flag wiring (exact)

In `procROP` (33461), add alongside existing flag parsing (33485-33528):
```python
optimize   = "optimize" in args
strictbad  = "strictbad" in args
candidates = 3
if "candidates" in args:
    v, ok = getIntArg(args["candidates"])
    if ok: candidates = max(1, min(10, v))
```
Thread through the call (33539): `findROPGADGETS(..., technique, optimize, candidates, strictbad)`. Add params with defaults `optimize=False, candidates=3, strictbad=False` so every existing caller is unaffected. Pass into `createRopChains(..., optimize, candidates, strictbad)` at 26030 (same default-param treatment). Update `ropUsage` help text.

---

## 5. Phased plan

| Phase | Deliverable | Behavior change | Depends |
|---|---|---|---|
| P0 | Golden-output test harness on a checked-in sample module | none | — |
| P1 | `GadgetEffect` + `parseGadgetEffect` + `scoreGadget` + `getBestGadget`, cache built in discovery | none (flag off) | P0 |
| P2 | Bad-char tagging + soft-exclude in `findROPGADGETS` | none (flag off) | P1 |
| P3 | State model + Dijkstra selection in `createRopChains` under `-optimize` | opt-in | P1,P2 |
| P4 | Yen k-shortest + ranked `rop.md` append (`-candidates N`) | opt-in | P3 |
| P5 | `scoreModule` ordering | opt-in | P1 |
| P6 | Docs, `ropUsage`, release notes; keep legacy default | none | all |

Each phase independently reviewable; P1/P2 land dormant behind the flag.

---

## 6. Test strategy

Debugger-free unit tests (plain dicts/strings) — most of the suite runs in CI without Immunity/WinDbg:
- `scoreGadget`: literal assertions incl. the two spec examples (good ≫ bad).
- `parseGadgetEffect`: table `instr_str -> expected (reg_writes, clobbers, mem_writes, stack_delta, ending)`. Cross-check `stack_delta == getJunk(chain)` for a corpus.
- `Transition.apply`: precondition/clobber correctness.
- State search: synthetic pool proves `EAX→EBX` picks `mov`, not `push/pop`; proves it won't clobber a finished reg when an alternative exists.
- Yen: returns distinct, cost-ordered chains.
- Bad-char: soft-exclude ordering; strict mode hard-excludes.
- Golden: full `rop` (no flag) diff-identical to pre-change output on sample module.
- Property: emitted chain, simulated over the state model, reaches goal register state.

Provide a tiny fake-gadget fixture builder so tests need no live process.

---

## 7. Performance

- `parseGadgetEffect`/`scoreGadget`: one pass per gadget at discovery; reuse `_invalid_instr_cache` style memoization. Negligible vs existing disasm cost.
- Dijkstra: bounded to goal-relevant regs (≤7) and capped node budget; A\* heuristic prunes. Cap-hit → legacy fallback, logged.
- Yen: k×Dijkstra, k≤10. Acceptable for opt-in.
- Net: default path slightly *faster* (deterministic argmax replaces `random.choice` full-dict shuffle in the opt path only; legacy untouched).

---

## 8. Risks / limitations

- State model ignores EFLAGS, partial-reg writes (`al`/`ax`), memory aliasing → must degrade to `UNKNOWN`/clobber, never assert false control. Heuristic, not proven-correct (no live simulation).
- `stack_delta` must exactly equal `getJunk` accounting or filler math breaks chains → enforced by cross-check test.
- Determinism shift only in opt path; legacy output preserved to avoid breaking scripts.
- Scope discipline: no 64-bit, no JOP, no new API recipes in this effort.

---

## 9. Open items for reviewer

1. Score weights in §3.2 are a starting calibration — approve or tune after P1 on real corpus.
2. Default `k` (proposed 3) and node cap (proposed 20000) — confirm.
3. Flag names: `-optimize`, `-candidates N`, `-strictbad` — confirm naming before wiring.
4. Sample module for golden/CI fixtures — which DLL from `testing/`?
