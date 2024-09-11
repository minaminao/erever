from .colors import Colors
from .utils import UINT256_MAX, decode_printable_with_color, pad_even


class Stack:
    stack: list[int]
    ignore_stack_underflow: bool

    updated_indices_for_colorize: list[int]

    def __init__(self, ignore_stack_underflow: bool = False) -> None:
        self.stack = []
        self.ignore_stack_underflow = ignore_stack_underflow

        self.updated_indices_for_colorize = []

    def push(self, x: int) -> None:
        assert 0 <= x <= UINT256_MAX
        self.stack.append(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1]

    def extend(self, x: list[int]) -> None:
        assert 0 <= max(x) <= UINT256_MAX
        self.stack.extend(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1 - i for i in range(len(x))]

    def pop(self) -> int:
        if len(self.stack) == 0:
            if self.ignore_stack_underflow:
                return 0
            else:
                raise Exception("Stack underflow")
        return self.stack.pop()

    def __getitem__(self, i: int) -> int:
        if i >= len(self.stack):
            if self.ignore_stack_underflow:
                return 0
            else:
                raise Exception("Stack underflow")
        return self.stack[i]

    def clear(self) -> None:
        self.stack = []

    def to_string(self) -> str:
        ret = ""
        n = len(self.stack)
        for i in range(n):
            if i != 0:
                ret += ", "
            if isinstance(self.stack[n - 1 - i], int):
                x = pad_even(hex(self.stack[n - 1 - i]))
            else:
                x = str(self.stack[n - 1 - i])
            if n - 1 - i in self.updated_indices_for_colorize:
                x = Colors.GREEN + x + Colors.ENDC
            ret += x
        ret = "[" + ret + "]"
        return ret

    def to_string_with_decode(self) -> str:
        ret = ""
        n = len(self.stack)
        for i in range(n):
            if i != 0:
                ret += ", "
            if isinstance(self.stack[n - 1 - i], int):
                x = decode_printable_with_color(pad_even(hex(self.stack[n - 1 - i]))[2:])
            else:
                x = str(self.stack[n - 1 - i])
            if n - 1 - i in self.updated_indices_for_colorize:
                x = Colors.GREEN + x + Colors.ENDC
            ret += x
        ret = "[" + ret + "]"
        return ret

    def __len__(self) -> int:
        return len(self.stack)
