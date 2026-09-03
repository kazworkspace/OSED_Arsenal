"""
Tests for BackwardDataFlow — argument recovery from x86 call sites.

Each test assembles a real byte sequence, disassembles it with capstone,
then verifies that the data-flow tracker correctly classifies each argument.
"""
import pytest
from .conftest import make_instructions, PROLOGUE, MEMCPY_CALL, STRCPY_CALL

from bo_scanner.dataflow import BackwardDataFlow, ValType


IMAGE_BASE = 0x00400000


def _build_func(body: bytes, start: int = 0x00401000) -> list:
    return make_instructions(PROLOGUE + body, start)


class TestMemcpyArgumentRecovery:
    """
    memcpy([ebp-0x40], [ebp+0x08], [ebp+0x0c])

    Pushed right-to-left:
        push [ebp+0x0c]  → arg[2] = size
        push [ebp+0x08]  → arg[1] = src
        push eax         → arg[0] = dest  (eax set by LEA eax, [ebp-0x40])
    """

    def setup_method(self):
        self.insns = _build_func(MEMCPY_CALL)
        # CALL is the last instruction
        self.call_idx = len(self.insns) - 1
        self.df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE)
        self.args = self.df.recover_arguments(num_args=3)

    def test_recovers_three_arguments(self):
        assert len(self.args) >= 3

    def test_destination_is_stack_local(self):
        dest = self.args[0]
        assert dest.type == ValType.STACK_LOCAL, (
            f"Expected STACK_LOCAL, got {dest.type}: {dest.description}"
        )

    def test_destination_is_address_of_buffer(self):
        dest = self.args[0]
        # LEA → is_address should be True
        assert dest.is_address is True

    def test_destination_ebp_offset_is_negative_64(self):
        dest = self.args[0]
        assert dest.ebp_offset == -0x40, (
            f"Expected -0x40 (-64), got {dest.ebp_offset}"
        )

    def test_source_is_function_argument(self):
        src = self.args[1]
        assert src.type == ValType.FUNC_ARG, (
            f"Expected FUNC_ARG, got {src.type}: {src.description}"
        )

    def test_source_argument_index_is_zero(self):
        # [ebp+0x08] → caller arg #0
        src = self.args[1]
        assert src.arg_index == 0

    def test_length_is_function_argument(self):
        length = self.args[2]
        assert length.type == ValType.FUNC_ARG, (
            f"Expected FUNC_ARG for length, got {length.type}: {length.description}"
        )

    def test_length_argument_index_is_one(self):
        # [ebp+0x0c] → caller arg #1
        length = self.args[2]
        assert length.arg_index == 1


class TestStrcpyArgumentRecovery:
    """
    strcpy([ebp-0x40], 0x403000)

    Push order:
        push 0x403000  → arg[1] = src (constant)
        push eax       → arg[0] = dest ([ebp-0x40] via LEA)
    """

    def setup_method(self):
        self.insns = _build_func(STRCPY_CALL)
        self.call_idx = len(self.insns) - 1
        self.df = BackwardDataFlow(self.insns, self.call_idx, IMAGE_BASE)
        self.args = self.df.recover_arguments(num_args=2)

    def test_destination_is_stack_local(self):
        assert self.args[0].type == ValType.STACK_LOCAL

    def test_source_is_immediate_constant(self):
        src = self.args[1]
        assert src.type == ValType.IMMEDIATE, (
            f"Expected IMMEDIATE for constant string pointer, got {src.type}"
        )
        assert src.imm_value == 0x00403000


class TestStackFrameSize:
    """stack.py: get_stack_frame_size should extract 0x40 from the prologue."""

    def test_frame_size_extracted(self):
        from bo_scanner.stack import get_stack_frame_size
        insns = make_instructions(PROLOGUE + MEMCPY_CALL)
        size = get_stack_frame_size(insns)
        assert size == 0x40, f"Expected 0x40, got {size}"


class TestArgumentValueStr:
    """ArgumentValue.__str__ produces human-readable descriptions."""

    def test_immediate_str(self):
        from bo_scanner.dataflow import ArgumentValue
        v = ArgumentValue(type=ValType.IMMEDIATE, imm_value=0x40)
        assert "40" in str(v).upper()

    def test_stack_local_str(self):
        from bo_scanner.dataflow import ArgumentValue
        v = ArgumentValue(type=ValType.STACK_LOCAL, ebp_offset=-0x40)
        s = str(v)
        assert "EBP" in s.upper()
        assert "40" in s.upper()

    def test_func_arg_str(self):
        from bo_scanner.dataflow import ArgumentValue
        v = ArgumentValue(type=ValType.FUNC_ARG, ebp_offset=0x08, arg_index=0)
        s = str(v)
        assert "argument" in s.lower()
