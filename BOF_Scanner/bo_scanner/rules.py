"""
Dangerous API database.

Argument indices are 0-based, left-to-right (first/leftmost parameter = 0).
In x86 cdecl/stdcall arguments are pushed right-to-left, so the first push
found scanning backward from a CALL = arg[0].

New in this version:
  format_arg   — index of the format-string parameter (CAT_FORMAT_STRING rules)
  CAT_FORMAT_STRING — format string injection category (snprintf, printf, etc.)
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Set

# ── Categories ──────────────────────────────────────────────────────────────
CAT_UNBOUNDED_COPY   = "unbounded_string_copy"
CAT_SIZE_DEPENDENT   = "size_dependent_copy"
CAT_FORMATTED_INPUT  = "formatted_input"
CAT_FORMAT_STRING    = "format_string_injection"


@dataclass(frozen=True)
class APIRule:
    name: str
    category: str
    dest_arg: Optional[int]    # 0-based index of destination buffer argument
    src_arg: Optional[int]     # 0-based index of source / input argument
    size_arg: Optional[int]    # 0-based index of size argument (None = unbounded)
    base_risk: int             # 0–100 starting score
    num_args: int              # expected argument count (-1 = variadic)
    description: str
    format_arg: Optional[int] = None  # 0-based index of format string argument


# ── Primary rule entries ─────────────────────────────────────────────────────
_RULES: list = [
    # --- Unbounded string copy --------------------------------------------------
    APIRule("strcpy",   CAT_UNBOUNDED_COPY,  dest_arg=0, src_arg=1, size_arg=None,
            base_risk=85, num_args=2,
            description="Copies string to destination without length bound"),

    APIRule("strcat",   CAT_UNBOUNDED_COPY,  dest_arg=0, src_arg=1, size_arg=None,
            base_risk=80, num_args=2,
            description="Appends string to destination without length bound"),

    APIRule("gets",     CAT_UNBOUNDED_COPY,  dest_arg=0, src_arg=None, size_arg=None,
            base_risk=95, num_args=1,
            description="Reads unbounded line from stdin into buffer"),

    APIRule("sprintf",  CAT_UNBOUNDED_COPY,  dest_arg=0, src_arg=1, size_arg=None,
            base_risk=75, num_args=-1, format_arg=1,
            description="Formats string into destination without output length limit; "
                        "format arg may be user-controlled"),

    APIRule("vsprintf", CAT_UNBOUNDED_COPY,  dest_arg=0, src_arg=1, size_arg=None,
            base_risk=75, num_args=3, format_arg=1,
            description="Formats string (va_list) without output length limit"),

    # --- Size-dependent copy ----------------------------------------------------
    APIRule("memcpy",   CAT_SIZE_DEPENDENT,  dest_arg=0, src_arg=1, size_arg=2,
            base_risk=60, num_args=3,
            description="Memory copy; exploitable if size is attacker-controlled"),

    APIRule("memmove",  CAT_SIZE_DEPENDENT,  dest_arg=0, src_arg=1, size_arg=2,
            base_risk=55, num_args=3,
            description="Overlapping memory move; exploitable if size is attacker-controlled"),


    APIRule("strncpy",  CAT_SIZE_DEPENDENT,  dest_arg=0, src_arg=1, size_arg=2,
            base_risk=30, num_args=3,
            description="Bounded string copy; overflow if size > sizeof(dest) or "
                        "dest buffer passed to unbounded secondary function"),

    APIRule("strncat",  CAT_SIZE_DEPENDENT,  dest_arg=0, src_arg=1, size_arg=2,
            base_risk=30, num_args=3,
            description="Bounded string append; overflow if size > remaining space in dest"),

    APIRule("recv",     CAT_SIZE_DEPENDENT,  dest_arg=1, src_arg=None, size_arg=2,
            base_risk=70, num_args=4,
            description="Receives network data into buffer; len from caller"),

    APIRule("recvfrom", CAT_SIZE_DEPENDENT,  dest_arg=1, src_arg=None, size_arg=2,
            base_risk=70, num_args=6,
            description="Receives UDP datagram into buffer; len from caller"),

    APIRule("ReadFile", CAT_SIZE_DEPENDENT,  dest_arg=1, src_arg=None, size_arg=2,
            base_risk=55, num_args=5,
            description="Reads file data into buffer; byte count from caller"),

    # --- Formatted input --------------------------------------------------------
    APIRule("scanf",    CAT_FORMATTED_INPUT, dest_arg=1, src_arg=0, size_arg=None,
            base_risk=80, num_args=-1,
            description="Formatted input without field-width length specifiers"),

    APIRule("sscanf",   CAT_FORMATTED_INPUT, dest_arg=2, src_arg=1, size_arg=None,
            base_risk=70, num_args=-1,
            description="String-parsed input without field-width length specifiers"),

    APIRule("fscanf",   CAT_FORMATTED_INPUT, dest_arg=2, src_arg=1, size_arg=None,
            base_risk=75, num_args=-1,
            description="File-stream formatted input; %[...] and %s without width "
                        "specifier overflow the destination buffer"),

    # --- Format string injection ------------------------------------------------
    # snprintf(buf, size, fmt, ...) — bounded write but format may be user-controlled
    APIRule("snprintf",  CAT_FORMAT_STRING,  dest_arg=0, src_arg=None, size_arg=1,
            base_risk=65, num_args=-1, format_arg=2,
            description="snprintf with potentially user-controlled format string; "
                        "enables %n write, %x/%s read-past-buffer"),

    APIRule("printf",    CAT_FORMAT_STRING,  dest_arg=None, src_arg=None, size_arg=None,
            base_risk=70, num_args=-1, format_arg=0,
            description="printf with potentially user-controlled format string"),

    APIRule("fprintf",   CAT_FORMAT_STRING,  dest_arg=None, src_arg=None, size_arg=None,
            base_risk=65, num_args=-1, format_arg=1,
            description="fprintf with potentially user-controlled format string"),

    APIRule("vprintf",   CAT_FORMAT_STRING,  dest_arg=None, src_arg=None, size_arg=None,
            base_risk=65, num_args=2, format_arg=0,
            description="vprintf with potentially user-controlled format string"),

    APIRule("vsnprintf", CAT_FORMAT_STRING,  dest_arg=0, src_arg=None, size_arg=1,
            base_risk=60, num_args=-1, format_arg=2,
            description="vsnprintf with potentially user-controlled format string"),
]

# ── Build registry ───────────────────────────────────────────────────────────
_REGISTRY: Dict[str, APIRule] = {r.name: r for r in _RULES}

# Aliases: CRT-decorated names, Win32 wrappers
_ALIASES: Dict[str, str] = {
    "_strcpy":    "strcpy",
    "_strcat":    "strcat",
    "_gets":      "gets",
    "_sprintf":   "sprintf",
    "_vsprintf":  "vsprintf",
    "_memcpy":    "memcpy",
    "_memmove":   "memmove",
    "_scanf":     "scanf",
    "_sscanf":    "sscanf",
    "_fscanf":    "fscanf",
    "_strncpy":   "strncpy",
    "_strncat":   "strncat",
    "_snprintf":  "snprintf",
    "_printf":    "printf",
    "_fprintf":   "fprintf",
    # Win32 ANSI wrappers
    "lstrcpyA":   "strcpy",
    "lstrcatA":   "strcat",
    # msvcrt forwarding names (safe variants — excluded from flagging)
    "memcpy_s":   None,
    "strcpy_s":   None,
    "strcat_s":   None,
    "sprintf_s":  None,
    "snprintf_s": None,
}


def get_rule(name: str) -> Optional[APIRule]:
    """Return the APIRule for a given import name, following aliases."""
    canonical = _ALIASES.get(name, name)
    if canonical is None:
        return None  # explicitly excluded safe variant
    return _REGISTRY.get(canonical)


def get_all_dangerous_names() -> Set[str]:
    """Return every name (canonical + alias) that should be watched."""
    names = set(_REGISTRY.keys())
    names.update(k for k, v in _ALIASES.items() if v is not None)
    return names


# ── Indirect call sentinel ────────────────────────────────────────────────────
CAT_INDIRECT_UNRESOLVED = "indirect_call_unresolved"

UNRESOLVED_INDIRECT_RULE = APIRule(
    name="unresolved indirect call",
    category=CAT_INDIRECT_UNRESOLVED,
    dest_arg=None,
    src_arg=None,
    size_arg=None,
    base_risk=5,
    num_args=0,
    description=(
        "Indirect call whose target could not be resolved via IAT or thunk. "
        "May or may not target a dangerous API — manual review required."
    ),
)
