from .colors import Colors
from .utils import UINT256_MAX, decode_printable_with_color, pad_even


class Stack:
    def __init__(self, ignore_stack_underflow: bool = False):
        self.stack = []
        self.ignore_stack_underflow = ignore_stack_underflow

        self.updated_indices_for_colorize = []

    def push(self, x: int):
        assert x <= UINT256_MAX
        self.stack.append(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1]

    def extend(self, x: list):
        assert max(x) <= UINT256_MAX
        self.stack.extend(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1 - i for i in range(len(x))]

    def pop(self):
        if len(self.stack) == 0:
            if self.ignore_stack_underflow:
                return 0
            else:
                raise Exception("Stack underflow")
        return self.stack.pop()

    def clear(self):
        self.stack = []

    def to_string(self):
        ret = ""
        n = len(self.stack)
        for i in range(n):
            if i != 0:
                ret += ", "
            if type(self.stack[n - 1 - i]) == int:
                x = pad_even(hex(self.stack[n - 1 - i]))
            else:
                x = self.stack[n - 1 - i]
            if n - 1 - i in self.updated_indices_for_colorize:
                x = Colors.GREEN + x + Colors.ENDC
            ret += x
        ret = "[" + ret + "]"
        return ret

    def to_string_with_decode(self):
        ret = ""
        n = len(self.stack)
        for i in range(n):
            if i != 0:
                ret += ", "
            if type(self.stack[n - 1 - i]) == int:
                x = decode_printable_with_color(pad_even(hex(self.stack[n - 1 - i]))[2:])
            else:
                x = self.stack[n - 1 - i]
            if n - 1 - i in self.updated_indices_for_colorize:
                x = Colors.GREEN + x + Colors.ENDC
            ret += x
        ret = "[" + ret + "]"
        return ret
