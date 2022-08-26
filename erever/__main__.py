import argparse
from .opcodes import OPCODES
from .colors import colors
from .utils import *


def main():
    parser = argparse.ArgumentParser(description="EVM Reversing Tools")
    parser.add_argument("-b", "--bytecode")
    parser.add_argument("-f", "--filename")
    args = parser.parse_args()

    if args.bytecode:
        disassemble(args.bytecode)
    elif args.filename:
        data = open(args.filename).read()
        disassemble(data)


class Stack:
    def __init__(self):
        self.stack = []

        self.updated_indices_for_colorize = []

    def push(self, x: int):
        self.stack.append(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1]

    def extend(self, x: list[int]):
        self.stack.extend(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1 - i for i in range(len(x))]

    def pop(self) -> int:
        return self.stack.pop()

    def __str__(self):
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
                x = colors.YELLOW + x + colors.ENDC
            ret += x
        ret = "[" + ret + "]"
        return ret


class Memory:
    def __init__(self):
        self.memory = []

        self.mstore_l_for_colorize = None
        self.mstore_r_for_colorize = None

    def __extend(self, length: int):
        if len(self.memory) >= length:
            return
        self.memory += [0] * (length - len(self.memory))

    def get_hex(self, l: int, r: int) -> str:
        return bytes(self.memory[l:r]).hex()

    def mstore(self, offset: int, value: bytes):
        l = 32 - len(value)
        r = offset + 32
        self.__extend(r)
        for i, b in enumerate(value):
            self.memory[offset + l + i] = b

        self.mstore_l_for_colorize = offset + l
        self.mstore_r_for_colorize = r

    def mstore8(self, offset: int, value: int):
        self.__extend(offset + 1)
        self.memory[offset] = value

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = offset + 1

    def __str__(self):
        return bytes(self.memory).hex()

    def colorize(self):
        ret = str(self)
        if self.mstore_l_for_colorize:
            ret = ret[:2 * self.mstore_l_for_colorize] + colors.YELLOW + ret[2 * self.mstore_l_for_colorize:2 * self.mstore_r_for_colorize] + colors.ENDC + ret[2 * self.mstore_r_for_colorize:]
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None
        return ret


def disassemble(bytecode):
    bytecode = bytes.fromhex(bytecode)
    stack = Stack()
    memory = Memory()
    LOCATION_PAD_N = len(hex(len(bytecode))[2:])

    i = 0
    while i < len(bytecode):
        value = bytecode[i]
        name, stack_input_count, stack_output_count, description = OPCODES[value]
        print(f"{pad(hex(i), LOCATION_PAD_N)}: {name}", end="")

        if name.startswith("PUSH"):
            d = int(name[4:])
            v = bytes_to_long(bytecode[i + 1:i + 1 + d])
            print(" " + pad_even(hex(v)), end="")
            i += d

            stack.push(v)

        input = []
        for _ in range(stack_input_count):
            input.append(stack.pop())

        output = []
        if name.startswith("DUP"):
            d = int(name[3:])
            output = [input[d - 1]] + input[::]
            stack.extend(output[::-1])
        if name == "MSTORE":
            memory.mstore(input[0], long_to_bytes(input[1]))
        if name == "MSTORE8":
            memory.mstore8(input[0], input[1])
        if name == "CALLVALUE":
            stack.push("callvalue")
        if name == "ISZERO":
            x = stack.pop()
            if type(x) == int:
                if x > 0:
                    stack.push(0)
                else:
                    stack.push(1)
            else:
                stack.push(f"!({x})")
        if name == "RETURN":
            print(f"\n\treturn\t{memory.get_hex(input[0], input[0] + input[1])}")
            break

        print(f"\n\tstack\t{stack}", end="")
        print(f"\n\tmemory\t{memory.colorize()}", end="")

        print()
        i += 1


if __name__ == '__main__':
    main()