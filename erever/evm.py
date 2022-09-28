from Crypto.Hash import keccak

from .colors import *
from .opcodes import *
from .utils import *


class Context:
    DEFAULT_ADDRESS = 0
    DEFAULT_BALANCE = 0
    DEFAULT_ORIGIN = 0
    DEFAULT_CALLER = 0
    DEFAULT_CALLVALUE = 0
    DEFAULT_CALLDATA = b""
    DEFAULT_CALLDATA_HEX = ""
    DEFAULT_GASPRICE = 0
    DEFAULT_COINBASE = 0
    DEFAULT_TIMESTAMP = 0
    DEFAULT_NUMBER = 0
    DEFAULT_DIFFICULTY = 0
    DEFAULT_GASLIMIT = 0
    DEFAULT_CHAINID = 1
    DEFAULT_SELFBALANCE = 0
    DEFAULT_BASEFEE = 0
    DEFAULT_GAS = 0

    def from_arg_params_with_bytecode(args, bytecode):
        self = Context()
        self.bytecode = Context.__hex_to_bytes(bytecode)

        self.address = args.address
        self.balance = args.balance
        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = args.callvalue
        self.calldata = Context.__hex_to_bytes(args.calldata)
        self.gasprice = args.gasprice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = args.number
        self.difficulty = args.difficulty
        self.gaslimit = args.gaslimit
        self.chainid = args.chainid
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = args.gas
        return self

    def from_dict(d: dict):
        self = Context()
        self.bytecode = Context.__hex_to_bytes(d["bytecode"])

        self.address = d.get("address", Context.DEFAULT_ADDRESS)
        self.balance = d.get("balance", Context.DEFAULT_BALANCE)
        self.origin = d.get("origin", Context.DEFAULT_ORIGIN)
        self.caller = d.get("caller", Context.DEFAULT_CALLER)
        self.callvalue = d.get("callvalue", Context.DEFAULT_CALLVALUE)
        self.calldata = Context.__hex_to_bytes(d.get("calldata", Context.DEFAULT_CALLDATA_HEX))
        self.gasprice = d.get("gasprice", Context.DEFAULT_GASPRICE)
        self.coinbase = d.get("coinbase", Context.DEFAULT_COINBASE)
        self.timestamp = d.get("timestamp", Context.DEFAULT_TIMESTAMP)
        self.number = d.get("number", Context.DEFAULT_NUMBER)
        self.difficulty = d.get("difficulty", Context.DEFAULT_DIFFICULTY)
        self.gaslimit = d.get("gaslimit", Context.DEFAULT_GASLIMIT)
        self.chainid = d.get("chainid", Context.DEFAULT_CHAINID)
        self.selfbalance = d.get("selfbalance", Context.DEFAULT_SELFBALANCE)
        self.basefee = d.get("basefee", Context.DEFAULT_BASEFEE)
        self.gas = d.get("gas", Context.DEFAULT_GAS)
        return self

    def __hex_to_bytes(s: str):
        s = s.replace(" ", "").replace("\n", "")
        if s.startswith("0x"):
            s = s[2:]
        return bytes.fromhex(s)


class Stack:

    def __init__(self):
        self.stack = []

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

    def __extend(self, size: int):
        if size % 0x20 > 0:
            size += (0x20 - size % 0x20)
        if len(self.memory) >= size:
            return
        self.memory += [0] * (size - len(self.memory))

    def get_hex(self, l: int, r: int) -> str:
        return bytes(self.memory[l:r]).hex()

    def store8(self, offset: int, value: int):
        assert value < 0x100
        self.__extend(offset + 1)
        self.memory[offset] = value

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = offset + 1

    def store256(self, offset: int, value: int):
        value = value.to_bytes(32, "big")
        r = offset + 32
        self.__extend(r)
        for i, b in enumerate(value):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r

    def store(self, offset: int, value: bytes):
        r = offset + len(value)
        self.__extend(r)
        for i, b in enumerate(value):
            self.memory[offset + i] = b
        for i, b in enumerate(value):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r

    def load(self, offset: int):
        return bytes_to_long(bytes(self.memory[offset:offset+32]))

    def __str__(self):
        return bytes(self.memory).hex()

    def colorize(self):
        ret = str(self)
        if self.mstore_l_for_colorize is not None:
            ret = ret[:2 * self.mstore_l_for_colorize] + colors.GREEN + ret[2 * self.mstore_l_for_colorize:2 * self.mstore_r_for_colorize] + colors.ENDC + ret[2 * self.mstore_r_for_colorize:]
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None
        return ret


class Storage:
    def __init__(self):
        self.storage = {}

    def load(self, key):
        if key in self.storage:
            return self.storage[key]
        else:
            return 0

    def store(self, key, value):
        self.storage[key] = value


def disassemble(context, trace=False):
    stack = Stack()
    memory = Memory()
    storage = Storage()

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages = ""

    i = 0
    while i < len(context.bytecode):
        next_i = i + 1
        value = context.bytecode[i]
        if value in OPCODES:
            mnemonic, stack_input_count, stack_output_count, description, stack_input_names = OPCODES[value]
        else:
            mnemonic = colors.YELLOW + f"0x{value:02x} (?)" + colors.ENDC
            stack_input_count = 0
            stack_output_count = 0
            description = None

            warning_messages += f"The mnemonic for 0x{value:02x} in {pad(hex(i), LOCATION_PAD_N)} is not found.\n"

        if mnemonic == "JUMP" or mnemonic == "JUMPI":
            print(f"{pad(hex(i), LOCATION_PAD_N)}: {colors.CYAN + colors.BOLD + mnemonic + colors.ENDC}", end="")
        else:
            print(f"{pad(hex(i), LOCATION_PAD_N)}: {colors.BOLD + mnemonic + colors.ENDC}", end="")

        if mnemonic.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            push_v = bytes_to_long(context.bytecode[i + 1:i + 1 + mnemonic_num])
            print(" 0x" + context.bytecode[i+1:i+1+mnemonic_num].hex(), end="")
            next_i = i + 1 + mnemonic_num
            mnemonic = mnemonic[:4]
        elif mnemonic.startswith("DUP"):
            mnemonic_num = int(mnemonic[3:])
            mnemonic = mnemonic[:3]
        elif mnemonic.startswith("SWAP"):
            mnemonic_num = int(mnemonic[4:])
            mnemonic = mnemonic[:4]
        elif mnemonic.startswith("LOG"):
            mnemonic_num = int(mnemonic[3:])
            mnemonic = mnemonic[:3]

        if trace:
            input = []
            for _ in range(stack_input_count):
                input.append(stack.pop())

            if len(stack_input_names) > 0:
                print("(", end="")
                if mnemonic == "DUP":
                    if stack_input_count >= 2:
                        print("..., ", end="")
                    print(f"{pad_even(hex(input[-1]))}", end="")
                elif mnemonic == "SWAP":
                    if stack_input_count >= 2:
                        print(f"{pad_even(hex(input[0]))}, ..., {pad_even(hex(input[-1]))}", end="")
                    else:
                        print(f"{pad_even(hex(input[0]))}, {pad_even(hex(input[-1]))}", end="")
                else:
                    for i, name in enumerate(stack_input_names):
                        if i > 0:
                            print(", ", end="")
                        if name != "":
                            print(f"{name}:", end="")
                        print(f"{pad_even(hex(input[i]))}", end="")
                print(")", end="")

            match mnemonic:
                case "STOP":
                    break
                case "ADD":
                    stack.push(uint256(input[0] + input[1]))
                case "MUL":
                    stack.push(uint256(input[0] * input[1]))
                case "SUB":
                    stack.push(uint256(input[0] - input[1]))
                case "DIV":
                    if input[1] == 0:
                        stack.push(0)
                    else:
                        stack.push(input[0] // input[1])
                case "SDIV":
                    assert False
                case "MOD":
                    stack.push(input[0] % input[1])
                case "SMOD":
                    assert False
                case "ADDMOD":
                    stack.push((input[0] + input[1]) % input[2])
                case "MULMOD":
                    stack.push((input[0] * input[1]) % input[2])
                case "EXP":
                    stack.push(uint256(input[0] ** input[1]))
                case "SIGNEXTEND":
                    assert False
                case "LT":
                    stack.push(int(input[0] < input[1]))
                case "GT":
                    stack.push(int(input[0] > input[1]))
                case "SLT":
                    stack.push(int(int256(input[0] < int256(input[1]))))
                case "SGT":
                    stack.push(int(int256(input[0] > int256(input[1]))))
                case "EQ":
                    stack.push(int(input[0] == input[1]))
                case "ISZERO":
                    stack.push(int(input[0] == 0))
                case "AND":
                    stack.push(input[0] & input[1])
                case "OR":
                    stack.push(input[0] | input[1])
                case "XOR":
                    stack.push(input[0] ^ input[1])
                case "NOT":
                    stack.push((UINT256_MAX - 1) ^ input[0])
                case "BYTE":
                    if input[0] < 32:
                        stack.push(input[1].to_bytes(32, "big")[input[0]])
                    else:
                        stack.push(0)
                case "SHL":
                    stack.push(uint256(input[1] << input[0]))
                case "SHR":
                    stack.push(uint256(input[1] >> input[0]))
                case "SAR":
                    assert False
                case "KECCAK256":
                    print(f"\n\tinput\t{bytes(memory.memory[input[0]:input[0]+input[1]]).hex()}", end="")
                    k = keccak.new(digest_bits=256)
                    k.update(bytes(memory.memory[input[0]:input[0]+input[1]]))
                    stack.push(bytes_to_long(k.digest()))
                case "ADDRESS":
                    stack.push(context.address)
                case "BALANCE":
                    stack.push(context.balance)
                case "ORIGIN":
                    stack.push(context.origin)
                case "CALLER":
                    stack.push(context.caller)
                case "CALLVALUE":
                    stack.push(context.callvalue)
                case "CALLDATALOAD":
                    if len(context.calldata) < input[0]:
                        stack.push(0)
                    else:
                        stack.push(bytes_to_long((context.calldata[input[0]:] + b"\x00" * 32)[:32]))
                case "CALLDATASIZE":
                    stack.push(len(context.calldata))
                case "CALLDATACOPY":
                    # TODO: bound
                    memory.store(input[0], context.calldata[input[1]:input[1]+input[2]])
                case "CODESIZE":
                    stack.push(len(context.bytecode))
                case "CODECOPY":
                    # TODO: bound
                    memory.store(input[0], context.bytecode[input[1]:input[1]+input[2]])
                case "GASPRICE":
                    stack.push(context.callvalue)
                case "EXTCODESIZE":
                    assert False
                case "EXTCODECOPY":
                    assert False
                case "RETURNDATASIZE":
                    assert False
                case "RETURNDATACOPY":
                    assert False
                case "EXTCODEHASH":
                    assert False
                case "BLOCKHASH":
                    assert False
                case "COINBASE":
                    stack.push(context.coinbase)
                case "TIMESTAMP":
                    stack.push(context.timestamp)
                case "NUMBER":
                    stack.push(context.number)
                case "DIFFICULTY":
                    stack.push(context.difficulty)
                case "GASLIMIT":
                    stack.push(context.gaslimit)
                case "CHAINID":
                    stack.push(context.chainid)
                case "SELFBALANCE":
                    stack.push(context.selfbalance)
                case "BASEFEE":
                    stack.push(context.basefee)
                case "POP":
                    pass
                case "MLOAD":
                    stack.push(memory.load(input[0]))
                case "MSTORE":
                    memory.store256(input[0], input[1])
                case "MSTORE8":
                    memory.store8(input[0], input[1])
                case "SLOAD":
                    stack.push(storage.load(input[0]))
                case "SSTORE":
                    storage.store(input[0], input[1])
                case "JUMP":
                    assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST"
                    next_i = input[0]
                case "JUMPI":
                    assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST"
                    if input[1] != 0:
                        next_i = input[0]
                case "PC":
                    stack.push(i)
                case "MSIZE":
                    stack.push(len(memory.memory))
                case "GAS":
                    stack.push(context.gas)
                case "JUMPDEST":
                    pass
                case "PUSH":
                    stack.push(push_v)
                case "DUP":
                    stack.extend(input[::-1] + [input[mnemonic_num - 1]])
                case "SWAP":
                    top = input[0]
                    input[0] = input[mnemonic_num]
                    input[mnemonic_num] = top
                    stack.extend(input[::-1])
                case "LOG":
                    assert False
                case "CREATE":
                    assert False
                case "CALL":
                    assert False
                case "CALLCODE":
                    assert False
                case "RETURN":
                    print(f"\n\treturn\t{memory.get_hex(input[0], input[0] + input[1])}", end="")
                    break
                case "DELEGATECALL":
                    assert False
                case "CREATE2":
                    assert False
                case "STATICCALL":
                    assert False
                case "REVERT":
                    break
                case "INVALID":
                    break
                case "SELFDESTRUCT":
                    break

            print(f"\n\tstack\t{stack}", end="")
            print(f"\n\tmemory\t{memory.colorize()}", end="")

        print()
        i = next_i

    print()
    if warning_messages != "":
        print(colors.YELLOW + "WARNING:")
        print(warning_messages + colors.ENDC)
