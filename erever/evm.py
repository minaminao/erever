from Crypto.Hash import keccak
from web3 import Web3, HTTPProvider

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

        self.bytecode = bytes(code)
        
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
        self.gaslimit = args.gas
        self.chainid = args.chainid
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = args.gas
        # self.blockchash

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

    def colorize(self, line_length=0x20) -> list[str]:
        s = str(self)
        ret = []

        for i in range(0, len(s), 2 * line_length):
            ret.append(s[i:i + 2 * line_length])

        if self.mstore_l_for_colorize is not None:
            i_l = self.mstore_l_for_colorize // line_length
            j_l = 2 * (self.mstore_l_for_colorize % line_length)
            i_r = self.mstore_r_for_colorize // line_length
            j_r = 2 * (self.mstore_r_for_colorize % line_length)
            if j_r == 0:
                i_r -= 1
                j_r = 2 * line_length
            ret[i_r] = ret[i_r][:j_r] + colors.ENDC + ret[i_r][j_r:]
            ret[i_l] = ret[i_l][:j_l] + colors.GREEN + ret[i_l][j_l:]
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


def disassemble(context: Context, trace=False, entrypoint=0x00, n=UINT256_MAX):
    stack = Stack()
    memory = Memory()
    storage = Storage()

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages = ""

    i = entrypoint
    line_i = 0
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
                    pass
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
            # print()
            # print(bytes.fromhex(str(memory)).replace(b"\x00", b""), end="")
            lines = memory.colorize()
            for i, line in enumerate(lines):
                if i == 0:
                    print(f"\n\tmemory\t", end="")
                else:
                    print("\n\t\t", end="")
                print(f"{line}", end="")

        print()
        line_i += 1
        if line_i >= n:
            break
        i = next_i

    print()
    if warning_messages != "":
        print(colors.YELLOW + "WARNING:")
        print(warning_messages + colors.ENDC)


class Node:
    def __init__(self, type_, value):
        self.type = type_
        self.value = value

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
                    return f"(int256({self.value[0]}) / int256({self.value[1]}))"
                case "MOD":
                    return f"({self.value[0]} % {self.value[1]})"
                case "SMOD":
                    return f"(int256({self.value[0]}) % int256({self.value[1]}))"
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
                    return f"(int256({self.value[0]}) < int256({self.value[1]}))"
                case "SGT":
                    return f"(int256({self.value[0]}) > int256({self.value[1]}))"
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
                    return f"{self.value[0]} << {self.value[1]})"
                case "SHR":
                    return f"{self.value[0]} >> {self.value[1]})"
                case "SAR":
                    return f"int256({self.value[0]}) >> {self.value[1]})"
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
                    return colors.GRAY + f"{self.type}({str(self.value)[1:-1]})" + colors.ENDC
                # case "MLOAD":
                # case "MSTORE":
                # case "MSTORE8":
                # case "SLOAD":
                # case "SSTORE":
                # case "JUMP":
                # case "JUMPI":
                # case "PC":
                # case "MSIZE":
                # case "GAS":
                case "JUMPDEST":
                    return colors.CYAN + "JUMPDEST" + colors.ENDC
                # case "PUSH":
                # case "DUP":
                # case "SWAP":
                # case "LOG":
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
                    return f"{self.type}({str(self.value)[1:-1]})"


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


def disassemble_symbolic(context: Context, trace=False, entrypoint=0x00, show_symbolic_stack=False, n=UINT256_MAX):
    stack = SymbolicStack()

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages = ""

    i = entrypoint
    line_i = 0
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

        if mnemonic.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            push_v = bytes_to_long(context.bytecode[i + 1:i + 1 + mnemonic_num])
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

        input = []
        for _ in range(stack_input_count):
            input.append(stack.pop())

        match mnemonic:
            case "PUSH":
                stack.push(Node("uint256", push_v))
            case "DUP":
                stack.extend(input[::-1] + [input[mnemonic_num - 1]])
            case "SWAP":
                top = input[0]
                input[0] = input[mnemonic_num]
                input[mnemonic_num] = top
                stack.extend(input[::-1])
            case _:
                if trace and mnemonic == "JUMP":
                    if input[0].type == "uint256":
                        next_i = input[0].value

                assert stack_output_count <= 1
                if stack_output_count == 1:
                    stack.push(Node(mnemonic, input))
                else:
                    print(f"{pad(hex(i), LOCATION_PAD_N)}:", Node(mnemonic, input))
                    if show_symbolic_stack:
                        print(f"\tstack\t{stack}")
                    line_i += 1
                    if line_i >= n:
                        break

        i = next_i

    if warning_messages != "":
        print()
        print(colors.YELLOW + "WARNING:")
        print(warning_messages + colors.ENDC)
