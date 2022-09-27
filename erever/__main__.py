import argparse
from .opcodes import OPCODES
from .colors import colors
from .utils import *

ARGS = None
var_n = 0


def main():
    global ARGS
    parser = argparse.ArgumentParser(description="EVM Reversing Tools")
    parser.add_argument("-b", "--bytecode")
    parser.add_argument("-f", "--filename")
    parser.add_argument("--trace", action="store_true", default=False)
    # parser.add_argument("--tx", action="store_true", default=False)
    # parser.add_argument("--callvalue", type=int)
    # parser.add_argument("--chain-id", type=int)
    # parser.add_argument("--gas", type=int)
    # parser.add_argument("--calldata", type=str)
    # parser.add_argument("--rpc-url", type=str)
    ARGS = parser.parse_args()

    if ARGS.bytecode:
        disassemble(ARGS.bytecode)
    elif ARGS.filename:
        data = open(ARGS.filename).read().replace(" ", "").replace("\n", "")
        disassemble(data)


class Stack:
    def __init__(self):
        self.stack = []

        self.updated_indices_for_colorize = []

    def push(self, x):
        self.stack.append(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1]

    def extend(self, x: list):
        self.stack.extend(x)

        self.updated_indices_for_colorize = [len(self.stack) - 1 - i for i in range(len(x))]

    def pop(self):
        global var_n

        if len(self.stack) == 0:
            var_n += 1
            return "var_" + str(var_n)
        return self.stack.pop()

    def clear(self):
        self.stack = []

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
                x = colors.GREEN + x + colors.ENDC
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
        if self.mstore_l_for_colorize is not None:
            ret = ret[:2 * self.mstore_l_for_colorize] + colors.GREEN + ret[2 * self.mstore_l_for_colorize:2 * self.mstore_r_for_colorize] + colors.ENDC + ret[2 * self.mstore_r_for_colorize:]
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None
        return ret


def to_symbol(x):
    if type(x) is int:
        return pad_even(hex(x))
    else:
        return x


def disassemble(bytecode):
    bytecode = bytes.fromhex(bytecode)
    stack = Stack()
    memory = Memory()
    LOCATION_PAD_N = len(hex(len(bytecode))[2:])

    warning_messages = ""

    i = 0
    while i < len(bytecode):
        value = bytecode[i]
        if value in OPCODES:
            mnemonic, stack_input_count, stack_output_count, description = OPCODES[value]
        else:
            mnemonic = colors.YELLOW + f"0x{value:02x} (?)" + colors.ENDC
            stack_input_count = None
            stack_output_count = None
            description = None

            warning_messages += f"The mnemonic for 0x{value:02x} in {pad(hex(i), LOCATION_PAD_N)} is not found.\n"

        print(f"{pad(hex(i), LOCATION_PAD_N)}: {mnemonic}", end="")

        if mnemonic.startswith("PUSH"):
            d = int(mnemonic[4:])
            v = bytes_to_long(bytecode[i + 1:i + 1 + d])
            print(" " + pad(hex(v), d * 2), end="")
            i += d

            stack.push(v)

        if ARGS.trace:
            input = []
            for _ in range(stack_input_count):
                input.append(stack.pop())

            output = []
            if mnemonic.startswith("DUP"):
                d = int(mnemonic[3:])
                output = [input[d - 1]] + input[::]
                stack.extend(output[::-1])
            if mnemonic == "MSTORE":
                memory.mstore(input[0], long_to_bytes(input[1]))
            if mnemonic == "MSTORE8":
                memory.mstore8(input[0], input[1])
            if mnemonic == "CALLVALUE":
                stack.push("callvalue")
            if mnemonic == "CALLDATASIZE":
                stack.push("calldatasize")
            if mnemonic == "LT" or mnemonic == "GT":
                a, b = input[0], input[1]
                if type(a) is int and type(b) is int:
                    if mnemonic == "LT":
                        if a < b:
                            stack.push(1)
                        else:
                            stack.push(0)
                    if mnemonic == "GT":
                        if a > b:
                            stack.push(1)
                        else:
                            stack.push(0)
                else:
                    a = to_symbol(a)
                    b = to_symbol(b)
                    if " " in a:
                        a = "(" + a + ")"
                    if " " in b:
                        b = "(" + b + ")"
                    if mnemonic == "LT":
                        stack.push(f"{a} < {b}")
                    if mnemonic == "GT":
                        stack.push(f"{a} > {b}")
            if mnemonic == "ISZERO":
                x = input[0]
                if type(x) == int:
                    if x > 0:
                        stack.push(0)
                    else:
                        stack.push(1)
                else:
                    stack.push(f"ISZERO({x})")
            if mnemonic == "RETURN":
                print(f"\n\treturn\t{memory.get_hex(input[0], input[0] + input[1])}", end="")
            if mnemonic == "CALLDATALOAD":
                calldata_i = input[0]
                if type(calldata_i) is int:
                    r = to_symbol(calldata_i + 0x20)
                else:
                    r = f"{calldata_i}+0x20"
                stack.push(f"calldata[{calldata_i}:{r}]")
            if mnemonic == "SHR":
                shift, value = input[0], input[1]
                if type(shift) is int and type(value) is int:
                    stack.push(value >> shift)
                else:
                    stack.push(f"{to_symbol(value)} >> {to_symbol(shift)}")

        if ARGS.trace and mnemonic == "RETURN":
            break

        if ARGS.trace:
            print(f"\n\tstack\t{stack}", end="")
            print(f"\n\tmemory\t{memory.colorize()}", end="")

        print()
        i += 1

    print()
    if warning_messages != "":
        print(colors.YELLOW + "WARNING:")
        print(warning_messages + colors.ENDC)


if __name__ == '__main__':
    main()