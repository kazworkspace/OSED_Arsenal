"""
PE parsing using LIEF.

Extracts: image base, entry point, IAT map (iat_va → name),
and executable code sections with their raw bytes.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import lief


# IMAGE_SCN_MEM_EXECUTE — checked directly to avoid lief enum version drift
_SCN_MEM_EXECUTE = 0x20000000


@dataclass
class ImportEntry:
    name: str
    dll: str
    iat_va: int    # Virtual address of the IAT slot in the loaded image


@dataclass
class CodeSection:
    name: str
    va: int        # Virtual start address
    size: int
    data: bytes


@dataclass
class PEContext:
    path: str
    filename: str
    image_base: int
    entry_point_va: int
    architecture: str
    imports: List[ImportEntry] = field(default_factory=list)
    code_sections: List[CodeSection] = field(default_factory=list)
    # VA → ImportEntry — used by ImportResolver for fast lookup
    iat_map: Dict[int, ImportEntry] = field(default_factory=dict)
    # VA → exported function name (from the PE export table)
    export_names: Dict[int, str] = field(default_factory=dict)


def parse_pe(path: str) -> PEContext:
    """
    Parse a 32-bit Windows PE binary.
    Raises ValueError for non-PE or non-x86 files.
    """
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"lief could not parse: {path}")

    # Verify 32-bit x86
    machine = binary.header.machine
    if getattr(machine, "name", str(machine)) != "I386":
        raise ValueError(
            f"Expected x86 (I386) binary, got: {getattr(machine, 'name', str(machine))}. "
            "This tool supports 32-bit Windows PE only."
        )

    image_base = binary.optional_header.imagebase
    ep_va = image_base + binary.optional_header.addressof_entrypoint

    ctx = PEContext(
        path=path,
        filename=Path(path).name,
        image_base=image_base,
        entry_point_va=ep_va,
        architecture="x86",
    )

    # ── Imports ──────────────────────────────────────────────────────────────
    for imp in binary.imports:
        dll_name = imp.name.lower()
        for entry in imp.entries:
            if not entry.name:
                continue  # ordinal-only: skip
            # lief returns the RVA of the IAT slot; add image_base for the VA.
            # If the value already exceeds image_base it is already a VA —
            # handle both lief version behaviours.
            raw = entry.iat_address
            iat_va = raw if raw >= image_base else (image_base + raw)
            ie = ImportEntry(name=entry.name, dll=dll_name, iat_va=iat_va)
            ctx.imports.append(ie)
            ctx.iat_map[iat_va] = ie

    # ── Executable sections ───────────────────────────────────────────────────
    for sec in binary.sections:
        if not (sec.characteristics & _SCN_MEM_EXECUTE):
            continue
        sec_va = image_base + sec.virtual_address
        data = bytes(sec.content)
        ctx.code_sections.append(
            CodeSection(name=sec.name, va=sec_va, size=len(data), data=data)
        )

    if not ctx.code_sections:
        raise ValueError("No executable sections found — binary may be packed or corrupt.")

    # ── Export table (for DLLs and EXEs with symbols) ─────────────────────────
    try:
        if binary.has_exports:
            exp_dir = binary.get_export()
            for i in range(len(exp_dir.entries)):
                e = exp_dir.entries[i]
                if e.name and not e.is_forwarded:
                    exp_va = image_base + e.value
                    ctx.export_names[exp_va] = e.name
    except Exception:
        pass   # no export table, or lief version difference — silently skip

    return ctx
