import argparse
from erever.opcodes import OPCODES


def main():
    parser = argparse.ArgumentParser(description="EVM Reversing Tools")
    parser.add_argument("-b", "--bytecode")
    # parser.add_argument("-f", "--filename")
    args = parser.parse_args()

    if args.bytecode:
        disassemble(args.bytecode)


def bytes_to_long(x):
    return int.from_bytes(x, "big")


def long_to_bytes(x):
    return bytes.fromhex(hex(x)[2:])

def pad(hex_number: str, n: int):
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    hex_number = "0x" + "0" * (n - len(hex_number)) + hex_number
    return hex_number

def pad_even(hex_number: str):
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    n = len(hex_number) + len(hex_number) % 2
    return pad(hex_number, n)


class Stack:
    def __init__(self):
        self.stack = []

    def push(self, x: int):
        self.stack.append(x)

    def extend(self, x: list[int]):
        self.stack.extend(x)

    def pop(self) -> int:
        return self.stack.pop()

    def __str__(self):
        ret = ""
        n = len(self.stack)
        for i in range(n):
            if i != 0:
                ret += ", "
            ret += pad_even(hex(self.stack[n - 1 - i]))
        ret = "[" + ret + "]"
        return ret


class Memory:
    def __init__(self):
        self.memory = []

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

    def mstore8(self, offset: int, value: int):
        self.__extend(offset + 1)
        self.memory[offset] = value

    def __str__(self):
        return bytes(self.memory).hex()


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
        if name == "RETURN":
            print(f"\n\treturn\t{memory.get_hex(input[0], input[0] + input[1])}", end="")
            break

        print(f"\n\tstack\t{stack}", end="")
        print(f"\n\tmemory\t{memory}", end="")

        print()
        i += 1


if __name__ == '__main__':
    main()