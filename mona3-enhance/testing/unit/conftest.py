"""Debugger-free bootstrap for mona unit tests.

mona.py hard-requires a debugger backend (immlib / pykd+windbglib) at import
time. For pure-function unit tests (gadget scoring, parsing, cost search) we
stub a minimal `immlib` so mona imports headless with arch == 32.

Nothing here touches a live process; only pure functions are exercised.
"""
import os
import sys
import types
import importlib.util
from unittest.mock import MagicMock

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MONA_PATH = os.path.join(_REPO_ROOT, "mona.py")


def _load_mona():
    # Minimal immlib stub -> mona takes the Immunity branch, keeps arch = 32.
    fake_immlib = types.ModuleType("immlib")

    class LogBpHook:  # referenced by `from immlib import LogBpHook`
        pass

    fake_immlib.LogBpHook = LogBpHook
    fake_immlib.Debugger = MagicMock  # instantiated once at module load
    sys.modules["immlib"] = fake_immlib
    sys.modules.setdefault("immutils", types.ModuleType("immutils"))

    spec = importlib.util.spec_from_file_location("mona_headless", _MONA_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def mona():
    return _load_mona()


@pytest.fixture(autouse=True)
def _reset_rop_state(mona):
    """Reset per-run ROP state so tests don't leak via the ptr-keyed effect
    cache (real runs use unique addresses; tests reuse small ptrs)."""
    mona._gadget_effect_cache.clear()
    mona._rop_opt_ctx = None
    yield
    mona._gadget_effect_cache.clear()
    mona._rop_opt_ctx = None
