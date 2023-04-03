from Crypto.Hash import keccak
from Crypto.Util.number import bytes_to_long
from web3 import HTTPProvider, Web3
from enum import Enum
from collections import deque
from copy import deepcopy

from .colors import Colors
from .opcodes import OPCODES
from .utils import UINT256_MAX, uint256, int256, pad, pad_even, decode_printable_with_color, TAB_SIZE, SIGN_MASK


class Context:
    DEFAULT_ADDRESS = 0xadd2e55
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
    
    def from_tx_hash(args):
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        tx = w3.eth.get_transaction(args.tx)

        # Contract Creation
        if "to" not in tx or tx.to is None:
            self.bytecode = Context.__hex_to_bytes(tx.input)
            self.calldata = b""
        else:
            code = w3.eth.get_code(tx.to)
            # Contract
            if len(code) > 0:
                self.bytecode = bytes(code)
                self.calldata = Context.__hex_to_bytes(tx.input)
            # EOA
            else:
                self.bytecode = Context.__hex_to_bytes(tx.input)
                self.calldata = b""

        self.address = args.address
        self.balance = args.balance
        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = tx.value
        self.gasprice = tx.gasPrice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = tx.blockNumber
        self.difficulty = args.difficulty
        self.gaslimit = tx.gas
        self.chainid = int(tx.chainId, 16)
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = tx.gas
        # self.blockchash

        return self

    def from_contract_address(args):
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        code = w3.eth.get_code(args.contract_address)
        balance = w3.eth.get_balance(args.contract_address)

        self.bytecode = bytes(code)
        assert args.address == Context.DEFAULT_ADDRESS # TODO: priority
        self.address = Context.__hex_to_int(args.contract_address)
        assert args.balance == Context.DEFAULT_BALANCE
        self.balance = balance

        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = args.callvalue
        self.calldata = Context.__hex_to_bytes(args.calldata)
        self.gasprice = args.gasprice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = args.number
        self.difficulty = args.difficulty
        self.gaslimit = args.gas
        self.chainid = args.chainid
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = args.gas
        # self.blockchash

        return self


    def __hex_to_bytes(h: str | int):
        if type(h) is int:
            h = hex(h)
        h = h.replace(" ", "").replace("\n", "")
        if h.startswith("0x"):
            h = h[2:]
        return bytes.fromhex(h)

    def __hex_to_int(h: str):
        if h.startswith("0x"):
            return int(h, 16)
        else:
            return int(h)


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

    def get_hex(self, start: int, end: int) -> str:
        return bytes(self.memory[start:end]).hex()

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

    def to_string(self, line_length=0x20) -> list[str]:
        s = bytes(self.memory).hex()
        ret = []

        def zero_to_gray(s):
            ret = ""
            for i in range(0, len(s), 2):
                b = s[i:i+2]
                if b == "00":
                    ret += Colors.GRAY + b + Colors.ENDC
                else:
                    ret += b
            return ret

        for i in range(0, len(s), 2 * line_length):
            ret.append(s[i:i + 2 * line_length])

        decoded_lines = []
        for line in ret:
            decoded_line = decode_printable_with_color(line)
            decoded_lines.append(decoded_line)

        modified = []
        if self.mstore_l_for_colorize is not None:
            i_l = self.mstore_l_for_colorize // line_length
            j_l = 2 * (self.mstore_l_for_colorize % line_length)
            i_r = self.mstore_r_for_colorize // line_length
            j_r = 2 * (self.mstore_r_for_colorize % line_length)
            if j_r == 0:
                i_r -= 1
                j_r = 2 * line_length
            ret[i_r] = ret[i_r][:j_r] + Colors.ENDC + zero_to_gray(ret[i_r][j_r:])
            ret[i_l] = zero_to_gray(ret[i_l][:j_l]) + Colors.GREEN + ret[i_l][j_l:]
            modified.extend([i_l, i_r])
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None

        for i in range(0, len(ret)):
            if i in modified:
                ret[i] = ret[i] + " | " + decoded_lines[i]
            else:
                ret[i] = zero_to_gray(ret[i]) + " | " + decoded_lines[i]

        return ret


class Storage:
    def __init__(self):
        self.storage = {}

    def load(self, key):
        return self.storage.get(key, 0)

    def store(self, key, value):
        self.storage[key] = value


def disassemble(context: Context, trace=False, entrypoint=0x00, max_steps=UINT256_MAX, decode_stack=False, ignore_stack_underflow=False, silent=False, return_last_jump_to_address=False, hide_pc=False):
    stack = Stack(ignore_stack_underflow=ignore_stack_underflow)
    memory = Memory()
    storage = Storage()

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages = ""

    pc = entrypoint
    steps = 0
    last_jump_to_address = None
    while pc < len(context.bytecode):
        next_pc = pc + 1
        value = context.bytecode[pc]
        if value in OPCODES:
            mnemonic, stack_input_count, _stack_output_count, _description, stack_input_names = OPCODES[value]
        else:
            mnemonic = Colors.YELLOW + f"0x{value:02x} (?)" + Colors.ENDC
            stack_input_count = 0
            _stack_output_count = 0
            _description = None

            warning_messages += f"The mnemonic for 0x{value:02x} in {pad(hex(pc), LOCATION_PAD_N)} is not found.\n"

        if not silent:
            if not hide_pc:
                print(f"{pad(hex(pc), LOCATION_PAD_N)}: ", end="")
            if mnemonic == "JUMP" or mnemonic == "JUMPI":
                print(f"{Colors.CYAN}{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")
            elif mnemonic == "JUMPDEST":
                print(f"{Colors.BLUE}{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")
            else:
                print(f"{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")

        if mnemonic.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            push_v = bytes_to_long(context.bytecode[pc + 1:pc + 1 + mnemonic_num])
            if not silent:
                print(" 0x" + context.bytecode[pc+1:pc+1+mnemonic_num].hex(), end="")
            next_pc = pc + 1 + mnemonic_num
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

            if not silent:
                if len(stack_input_names) > 0:
                    print("(", end="")
                    if mnemonic == "DUP":
                        if mnemonic_num >= 2:
                            print("..., ", end="")
                        print(f"{pad_even(hex(input[-1]))}", end="")
                    elif mnemonic == "SWAP":
                        if mnemonic_num >= 2:
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
                    if input[1] == 0:
                        stack.push(0)
                    else:
                        stack.push(int256(input[0]) // int256(input[1]))
                case "MOD":
                    stack.push(input[0] % input[1])
                case "SMOD":
                    stack.push(int256(input[0]) % int256(input[1]))
                case "ADDMOD":
                    stack.push((input[0] + input[1]) % input[2])
                case "MULMOD":
                    stack.push((input[0] * input[1]) % input[2])
                case "EXP":
                    stack.push(uint256(input[0] ** input[1]))
                case "SIGNEXTEND":
                    bits = (input[0] + 1) * 8
                    mask = 1 << (bits - 1)
                    if input[1] & mask:
                        stack.push((1 << 256) - ((1 << bits) - input[1]))
                    else:
                        stack.push(input[1])
                case "LT":
                    stack.push(int(input[0] < input[1]))
                case "GT":
                    stack.push(int(input[0] > input[1]))
                case "SLT":
                    stack.push(int(int256(input[0]) < int256(input[1])))
                case "SGT":
                    stack.push(int(int256(input[0]) > int256(input[1])))
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
                    stack.push(input[1] >> input[0])
                case "SAR":
                    if input[1] & SIGN_MASK:
                        stack.push(((1 << 256) + (int256(input[1]) >> input[0])))
                    else:
                        stack.push(input[1] >> input[0])
                case "KECCAK256":
                    if not silent:
                        print(f"\n{'input'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{bytes(memory.memory[input[0]:input[0]+input[1]]).hex()}", end="")
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
                    # assert False
                    stack.push(0)
                case "EXTCODECOPY":
                    assert False
                case "RETURNDATASIZE":
                    # assert False
                    stack.push(0)
                case "RETURNDATACOPY":
                    # assert False
                    pass
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
                    next_pc = input[0]
                    last_jump_to_address = input[0]
                case "JUMPI":
                    assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST"
                    if input[1] != 0:
                        next_pc = input[0]
                    last_jump_to_address = input[0]
                case "PC":
                    stack.push(pc)
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
                    pass
                case "CREATE":
                    assert False
                case "CALL":
                    assert False
                case "CALLCODE":
                    assert False
                case "RETURN":
                    if not silent:
                        print(f"\n{'return'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{memory.get_hex(input[0], input[0] + input[1])}", end="")
                    break
                case "DELEGATECALL":
                    # assert False
                    pass
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

            if not silent:
                print(f"\n{'stack'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{stack.to_string()}", end="")
                if decode_stack:
                    print(f"\n{' ' * (TAB_SIZE * 3)}{stack.to_string_with_decode()}", end="")

                lines = memory.to_string()
                for pc, line in enumerate(lines):
                    if pc == 0:
                        print(f"\n{'memory'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}", end="")
                    else:
                        print(f"\n{' ' * (TAB_SIZE * 3)}", end="")
                    print(f"{line}", end="")

        if not silent:
            print()
        steps += 1
        if steps >= max_steps:
            break
        pc = next_pc

    if not silent:
        print()
        if warning_messages != "":
            print(Colors.YELLOW + "WARNING:")
            print(warning_messages + Colors.ENDC)
    
    if return_last_jump_to_address:
        return last_jump_to_address


class Node:
    def __init__(self, type_, value, mnemonic_num=None, input_count=None):
        self.type = type_
        self.value = value

        self.mnemonic_num = mnemonic_num
        self.input_count = input_count

    def unwrap(s):
        s = str(s)
        return s[1:-1] if s[0] == "(" and s[-1] == ")" else s

    def __repr__(self):
        if self.type == "uint256":
            return f"{pad_even(hex(self.value))}"
        elif self.type == "var":
            return self.value
        else:
            match self.type:
                # case "STOP":
                case "ADD":
                    return f"({self.value[0]} + {self.value[1]})"
                case "MUL":
                    return f"({self.value[0]} * {self.value[1]})"
                case "SUB":
                    return f"({self.value[0]} - {self.value[1]})"
                case "DIV":
                    return f"({self.value[0]} / {self.value[1]})"
                case "SDIV":
                    return f"(int256({Node.unwrap(self.value[0])}) / int256({Node.unwrap(self.value[1])}))"
                case "MOD":
                    return f"({self.value[0]} % {self.value[1]})"
                case "SMOD":
                    return f"(int256({Node.unwrap(self.value[0])}) % int256({Node.unwrap(self.value[1])}))"
                case "ADDMOD":
                    return f"(({self.value[0]} + {self.value[1]}) % {self.value[2]})"
                case "MULMOD":
                    return f"(({self.value[0]} * {self.value[1]}) % {self.value[2]})"
                case "EXP":
                    return f"({self.value[0]} ** {self.value[1]})"
                # case "SIGNEXTEND":
                case "LT":
                    return f"({self.value[0]} < {self.value[1]})"
                case "GT":
                    return f"({self.value[0]} > {self.value[1]})"
                case "SLT":
                    return f"(int256({Node.unwrap(self.value[0])}) < int256({Node.unwrap(self.value[1])}))"
                case "SGT":
                    return f"(int256({Node.unwrap(self.value[0])}) > int256({Node.unwrap(self.value[1])}))"
                case "EQ":
                    return f"({self.value[0]} == {self.value[1]})"
                # case "ISZERO":
                case "AND":
                    return f"({self.value[0]} & {self.value[1]})"
                case "OR":
                    return f"({self.value[0]} | {self.value[1]})"
                case "XOR":
                    return f"({self.value[0]} ^ {self.value[1]})"
                # case "NOT":
                # case "BYTE":
                case "SHL":
                    return f"({self.value[1]} << {self.value[0]})"
                case "SHR":
                    return f"({self.value[1]} >> {self.value[0]})"
                case "SAR":
                    return f"(int256({Node.unwrap(self.value[1])}) >> {self.value[0]})"
                # case "KECCAK256":
                # case "ADDRESS":
                # case "BALANCE":
                # case "ORIGIN":
                # case "CALLER":
                # case "CALLVALUE":
                # case "CALLDATALOAD":
                # case "CALLDATASIZE":
                # case "CALLDATACOPY":
                # case "CODESIZE":
                # case "CODECOPY":
                # case "GASPRICE":
                # case "EXTCODESIZE":
                # case "EXTCODECOPY":
                # case "RETURNDATASIZE":
                # case "RETURNDATACOPY":
                # case "EXTCODEHASH":
                # case "BLOCKHASH":
                # case "COINBASE":
                # case "TIMESTAMP":
                # case "NUMBER":
                # case "DIFFICULTY":
                # case "GASLIMIT":
                # case "CHAINID":
                # case "SELFBALANCE":
                # case "BASEFEE":
                case "POP":
                    return f"{Colors.GRAY}{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])})"
                # case "MLOAD":
                # case "MSTORE":
                # case "MSTORE8":
                # case "SLOAD":
                # case "SSTORE":
                case "JUMP":
                    return f"{Colors.CYAN}{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])})"
                case "JUMPI":
                    return f"{Colors.CYAN}{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])}, {Node.unwrap(self.value[1])})"
                # case "PC":
                # case "MSIZE":
                # case "GAS":
                case "JUMPDEST":
                    return f"{Colors.BLUE}{Colors.BOLD}{self.type}{Colors.ENDC}"
                case "PUSH":
                    return f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC} {self.value}"
                case "DUP":
                    ret = f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}("
                    if self.mnemonic_num >= 2:
                        ret += "..., "
                    ret += f"{str(self.value[-1])})"
                    return ret
                case "SWAP":
                    ret = f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}("
                    if self.mnemonic_num >= 2:
                        ret += f"{str(self.value[0])}, ..., {str(self.value[-1])})"
                    else:
                        ret += f"{str(self.value[0])}, {str(self.value[-1])})"
                    return ret
                case "LOG":
                    return f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}({str(self.value)[1:-1]})"
                # case "CREATE":
                # case "CALL":
                # case "CALLCODE":
                # case "RETURN":
                # case "DELEGATECALL":
                # case "CREATE2":
                # case "STATICCALL":
                # case "REVERT":
                # case "INVALID":
                # case "SELFDESTRUCT":
                case _:
                    if self.input_count == 1:
                        return f"{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])})"
                    else:
                        return f"{Colors.BOLD}{self.type}{Colors.ENDC}({str(self.value)[1:-1]})"


class SymbolicStack:
    def __init__(self):
        self.var_n = 0
        self.stack: list[Node] = []

    def push(self, x: Node):
        self.stack.append(x)

    def extend(self, x: list[Node]):
        self.stack.extend(x)

    def pop(self) -> Node:
        if len(self.stack) == 0:
            ret = Node("var", f"var_{self.var_n}")
            self.var_n += 1
            return ret
        else:
            return self.stack.pop()

    def clear(self):
        self.stack = []

    def __repr__(self):
        return repr(self.stack[::-1])
    
    def to_string(self):
        return self.__repr__()

def disassemble_symbolic(context: Context, entrypoint=0x00, show_symbolic_stack=False, max_steps=UINT256_MAX, hide_pc=False, hide_opcodes_with_no_stack_output=False):

    class State:
        def __init__(self, context: Context, entrypoint=0x00):
            self.context = context
            self.stack = SymbolicStack()
            self.pc = entrypoint
            
            self.steps = 0
            self.conditions = [] # [(condition, pc, is_met: bool)]
            self.jumped_from = None
            self.jumped = None

        def hash(self):
            # Contexts are not changed, so they can be ignored
            return hash((self.pc, self.stack.to_string()))
    
    initial_state = State(context, entrypoint)
    queue = deque()
    queue.append(initial_state)
    hashes = set()

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    while len(queue) > 0:
        state: State = queue.popleft()
        if state.hash() in hashes:
            continue
        hashes.add(state.hash())
        context = state.context
        stack = state.stack

        print(f"\n{Colors.BOLD}{pad(hex(state.pc), LOCATION_PAD_N)}{Colors.ENDC}", end="")
        if state.jumped_from is not None:
            if state.jumped:
                print(f" ({Colors.GREEN}<- {pad(hex(state.jumped_from), LOCATION_PAD_N)}{Colors.ENDC})")
            else:
                print(f" ({Colors.RED}<- {pad(hex(state.jumped_from), LOCATION_PAD_N)}{Colors.ENDC})")
            for condition, pc, is_met in state.conditions:
                if is_met:
                    print(f"  {Colors.GREEN} {pad(hex(pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.GREEN}== true{Colors.ENDC}")
                else:
                    print(f"  {Colors.RED} {pad(hex(pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.RED}== false{Colors.ENDC}")
        else:
            print()

        pc = state.pc
        while pc < len(context.bytecode):

            next_pc = pc + 1
            value = context.bytecode[pc]
            if value in OPCODES:
                mnemonic, stack_input_count, stack_output_count, _description, _stack_input_names = OPCODES[value]
            else:
                mnemonic = f"{Colors.YELLOW}0x{value:02x} (?){Colors.ENDC}"
                stack_input_count = 0
                stack_output_count = 0
                _description = None

            if mnemonic.startswith("PUSH"):
                mnemonic_num = int(mnemonic[4:])
                push_v = bytes_to_long(context.bytecode[pc + 1:pc + 1 + mnemonic_num])
                next_pc = pc + 1 + mnemonic_num
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
            else:
                mnemonic_num = None

            input = []
            for _ in range(stack_input_count):
                input.append(stack.pop())

            end = False
            match mnemonic:
                # 状態の操作はここに。操作しないものはNodeの__repr__に。
                case "STOP":
                    end = True
                case "PUSH":
                    stack.push(Node("uint256", push_v))
                case "DUP":
                    stack.extend(input[::-1] + [input[mnemonic_num - 1]])
                case "SWAP":
                    top = input[0]
                    input[0] = input[mnemonic_num]
                    input[mnemonic_num] = top
                    stack.extend(input[::-1])
                case "REVERT":
                    end = True
                case "INVALID":
                    end = True
                case "SELFDESTRUCT":
                    end = True
                case _:
                    assert stack_output_count <= 1
                    if stack_output_count == 1:
                        stack.push(Node(mnemonic, input))

            if hide_opcodes_with_no_stack_output and stack_output_count == 0:
                pass
            else:
                if not hide_pc:
                    print(f"{pad(hex(pc), LOCATION_PAD_N)}: ", end="")

                if mnemonic == "PUSH":
                    print(Node(mnemonic, "0x" + context.bytecode[pc+1:pc+1+mnemonic_num].hex(), mnemonic_num, stack_input_count))
                else:
                    res = str(Node(mnemonic, input, mnemonic_num, stack_input_count))
                    if res[0] == "(":
                        print(res[1:-1])
                    else:
                        print(res)

                if show_symbolic_stack:
                    print(f"{'stack'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{stack.to_string()}")

            if mnemonic == "JUMP" and input[0].type == "uint256":
                next_pc = input[0].value
            if mnemonic == "JUMPI" and input[0].type == "uint256":
                state.steps += 1
                state_not_jumped = deepcopy(state)
                state_not_jumped.pc = next_pc
                state_not_jumped.jumped_from = pc
                state_not_jumped.jumped = False
                state_not_jumped.conditions.append((input[1], pc, False))
                state_jumped = state
                state_jumped.pc = input[0].value
                state_jumped.jumped_from = pc
                state_jumped.jumped = True
                state_jumped.conditions.append((input[1], pc, True))
                queue.append(state_jumped)
                queue.append(state_not_jumped)
                break

            state.steps += 1
            if state.steps >= max_steps:
                break

            if end:
                break

            pc = next_pc


class ControlType(Enum):
    BEFORE_JUMPDEST = 0
    JUMP = 1
    JUMPI = 2
    END = 3
    BAD = -1


def disassemble_mermaid(context: Context, entrypoint=0x00, max_steps=UINT256_MAX, decode_stack=False):
    """
    ブロックの開始は0x00,JUMPDEST,JUMPIの一つ後。
    ブロックの終了はJUMP,JUMPDESTの一つ前,REVERT,INVALID,SELFDESTRUCT,STOP,RETURN。
    """

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    start_addresses = [0x00]

    for i in range(len(context.bytecode)):
        value = context.bytecode[i]
        if value not in OPCODES:
            continue
        mnemonic = OPCODES[value][0]
        if mnemonic == "JUMPDEST":
            # JUMPIの一つ後で追加済みならば追加しない
            if start_addresses[-1] != i:
                start_addresses.append(i)
        elif mnemonic == "JUMPI":
            start_addresses.append(i+1)
        
    def disassemble_block(start_address):
        """
        return is_valid_block, end_address, control_type, instructions
        """

        pc = start_address
        instructions = []
        while pc < len(context.bytecode):
            next_pc = pc + 1
            value = context.bytecode[pc]

            if value in OPCODES:
                mnemonic, stack_input_count, _stack_output_count, _description, stack_input_names = OPCODES[value]
            else:
                instructions.append(f"{pad(hex(pc), LOCATION_PAD_N)}: 0x (?)")
                return False, pc, ControlType.BAD, instructions

            if mnemonic.startswith("PUSH"):
                mnemonic_num = int(mnemonic[4:])
                next_pc = pc + 1 + mnemonic_num
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

            if mnemonic == "PUSH":
                instructions.append(f"{pad(hex(pc), LOCATION_PAD_N)}: {mnemonic}  0x{context.bytecode[pc+1:pc+1+mnemonic_num].hex()}")
            else:
                instructions.append(f"{pad(hex(pc), LOCATION_PAD_N)}: {mnemonic}")

            if pc != start_address and mnemonic == "JUMPDEST":
                return True, pc - 1, ControlType.BEFORE_JUMPDEST, instructions
            elif mnemonic == "JUMP":
                return True, pc, ControlType.JUMP, instructions
            elif mnemonic == "JUMPI":
                return True, pc, ControlType.JUMPI, instructions
            elif mnemonic in ["REVERT", "INVALID", "SELFDESTRUCT", "STOP", "RETURN"]:
                return True, pc, ControlType.END, instructions

            pc = next_pc
    

    graph = ""
    for start_address in start_addresses:
        is_valid_block, end_address, control_type, instructions = disassemble_block(start_address)
        if not is_valid_block:
            continue
        value = "\\n".join(instructions)
        max_steps = len(instructions)
        error = False
        try:
            last_jump_to_address = disassemble(context, True, start_address, max_steps, False, True, True, True)
        except Exception as e:
            error = True

        block_id = pad(hex(start_address), LOCATION_PAD_N) if start_address != entrypoint else "START"
        if error:
            graph += f"{block_id}({value}) --> ERROR\n"
            continue
        match control_type:
            case ControlType.BEFORE_JUMPDEST:
                next_block_id = pad(hex(end_address), LOCATION_PAD_N)
                graph += f"{block_id}({value}) --> {next_block_id}\n"
            case ControlType.JUMP:
                next_block_id = pad(hex(last_jump_to_address), LOCATION_PAD_N)
                graph += f"{block_id}({value}) --> {next_block_id}\n"
            case ControlType.JUMPI:
                next_block_id = pad(hex(last_jump_to_address), LOCATION_PAD_N)
                graph += f"{block_id}({value}) --> {next_block_id}\n"
                next_block_id = pad(hex(end_address + 1), LOCATION_PAD_N)
                graph += f"{block_id} --> {next_block_id}\n"
            case ControlType.END:
                next_block_id = "END"
                graph += f"{block_id}({value}) --> {next_block_id}\n"

    print("""<html lang="en">
    <head>
        <meta charset="utf-8" />
    </head>
    <body>""" + \
    f"""<pre class="mermaid">
            flowchart TB 
            {graph}
    </pre>""" + \
    """<script type="module">
      import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
      mermaid.initialize({ startOnLoad: true });
    </script>
    <style>
    .mermaid .node .label {
        text-align: left !important;
    }
    </style>
    </body>
    </html>
    """) 