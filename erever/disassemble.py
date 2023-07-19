from Crypto.Hash import keccak
from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .context import Context
from .memory import Memory
from .opcodes import OPCODES
from .stack import Stack
from .storage import Storage
from .utils import SIGN_MASK, TAB_SIZE, UINT256_MAX, int256, pad, pad_even, uint256


def disassemble(
    context: Context,
    trace: bool = False,
    entrypoint: int = 0x00,
    max_steps: int = UINT256_MAX,
    decode_stack: bool = False,
    ignore_stack_underflow: bool = False,
    silent: bool = False,
    return_last_jump_to_address: bool = False,
    return_disassembled_code: bool = False,
    hide_pc: bool = False,
    show_opcodes: bool = False,
    hide_memory: bool = False,
):
    disassembled_code = []
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
            if show_opcodes:
                print(f"{Colors.GRAY}(0x{context.bytecode[pc:pc+1].hex()}){Colors.ENDC} ", end="")
            if mnemonic == "JUMP" or mnemonic == "JUMPI":
                print(f"{Colors.CYAN}{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")
            elif mnemonic == "JUMPDEST":
                print(f"{Colors.BLUE}{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")
            else:
                print(f"{Colors.BOLD}{mnemonic}{Colors.ENDC}", end="")

        disassembled_code.append((pc, mnemonic))

        if mnemonic.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            push_v = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + mnemonic_num])
            if not silent and mnemonic_num > 0:
                print(" 0x" + context.bytecode[pc + 1 : pc + 1 + mnemonic_num].hex(), end="")
            next_pc = pc + 1 + mnemonic_num
            mnemonic = mnemonic[:4]
            disassembled_code.append((pc + 1, push_v))
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
            mnemonic_num = 0

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
                        print(
                            f"\n{'input'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{bytes(memory.memory[input[0]:input[0]+input[1]]).hex()}",
                            end="",
                        )
                    k = keccak.new(digest_bits=256)
                    k.update(bytes(memory.memory[input[0] : input[0] + input[1]]))
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
                        stack.push(bytes_to_long((context.calldata[input[0] :] + b"\x00" * 32)[:32]))
                case "CALLDATASIZE":
                    stack.push(len(context.calldata))
                case "CALLDATACOPY":
                    offset = input[1]
                    size = input[2]
                    if offset > len(context.calldata):
                        memory.store(input[0], b"\x00" * size)
                    elif offset + size > len(context.calldata):
                        memory.store(
                            input[0], context.calldata[offset:] + b"\x00" * (offset + size - len(context.calldata))
                        )
                    else:
                        memory.store(input[0], context.calldata[offset : offset + size])
                case "CODESIZE":
                    stack.push(len(context.bytecode))
                case "CODECOPY":
                    # TODO: bound
                    memory.store(input[0], context.bytecode[input[1] : input[1] + input[2]])
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
                    # TODO
                    stack.push(0xCA11)
                case "CALLCODE":
                    # TODO
                    stack.push(0xCA11)
                case "RETURN":
                    if not silent:
                        print(
                            f"\n{'return'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{memory.get_hex(input[0], input[0] + input[1])}",
                            end="",
                        )
                    break
                case "DELEGATECALL":
                    # TODO
                    stack.push(0xCA11)
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

        if trace and not silent:
            print(f"\n{'stack'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{stack.to_string()}", end="")
            if decode_stack:
                print(f"\n{' ' * (TAB_SIZE * 3)}{stack.to_string_with_decode()}", end="")

            if not hide_memory:
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
    elif return_disassembled_code:
        return disassembled_code
