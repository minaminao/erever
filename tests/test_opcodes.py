from erever.disassemble import disassemble
from erever.context import Context


def test_add() -> None:
    context = Context.from_dict(
        {"bytecode": "600a600a017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600101"}
    )
    result = disassemble(context, trace=True, return_trace_logs=True, silent=True)
    assert result.stack_after_execution.stack == [20, 0]
