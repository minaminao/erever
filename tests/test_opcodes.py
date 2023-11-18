from erever.context import Context
from erever.disassemble import disassemble


def test_add() -> None:
    context = Context(
        bytecode=bytes.fromhex(
            "600a600a017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600101"
        )
    )
    result = disassemble(context, trace=True, return_trace_logs=True, silent=True)
    assert result.stack_after_execution.stack == [20, 0]
