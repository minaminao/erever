from collections import deque
from copy import deepcopy
from enum import Enum

from Crypto.Hash import keccak
from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .context import Context
from .memory import Memory
from .node import Node
from .opcodes import OPCODES
from .stack import Stack
from .storage import Storage
from .symbolic_stack import SymbolicStack
from .utils import SIGN_MASK, TAB_SIZE, UINT256_MAX, int256, pad, pad_even, uint256


def disassemble(
    context: Context,
    trace=False,
    entrypoint=0x00,
    max_steps=UINT256_MAX,
    decode_stack=False,
    ignore_stack_underflow=False,
    silent=False,
    return_last_jump_to_address=False,
    hide_pc=False,
    show_opcodes=False,
    hide_memory=False,
):
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

        if mnemonic.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            push_v = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + mnemonic_num])
            if not silent and mnemonic_num > 0:
                print(" 0x" + context.bytecode[pc + 1 : pc + 1 + mnemonic_num].hex(), end="")
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


def disassemble_symbolic(
    context: Context,
    entrypoint=0x00,
    show_symbolic_stack=False,
    max_steps=UINT256_MAX,
    hide_pc=False,
    hide_instructions_with_no_stack_output=False,
    show_opcodes=False,
) -> None:
    class State:
        context: Context
        stack: SymbolicStack
        pc: int

        steps: int
        conditions: list[tuple[str, int, bool]]
        jumped_from: int | None
        jumped: bool | None

        def __init__(self, context: Context, entrypoint=0x00):
            self.context = context
            self.stack = SymbolicStack()
            self.pc = entrypoint

            self.steps = 0
            self.conditions = []  # [(condition, pc, is_met: bool)]
            self.jumped_from = None
            self.jumped = None

        def hash(self):
            # Contexts are not changed, so they can be ignored
            return hash((self.pc, self.stack.to_string()))

    initial_state = State(context, entrypoint)
    queue: deque[State] = deque()
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
                    print(
                        f"  {Colors.GREEN} {pad(hex(pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.GREEN}== true{Colors.ENDC}"
                    )
                else:
                    print(
                        f"  {Colors.RED} {pad(hex(pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.RED}== false{Colors.ENDC}"
                    )
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
                push_v = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + mnemonic_num])
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
                mnemonic_num = 0

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
                case "RETURN":
                    end = True
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

            if hide_instructions_with_no_stack_output and stack_output_count == 0:
                pass
            else:
                if not hide_pc:
                    print(f"{pad(hex(pc), LOCATION_PAD_N)}: ", end="")
                if show_opcodes:
                    print(f"{Colors.GRAY}(0x{context.bytecode[pc:pc+1].hex()}){Colors.ENDC} ", end="")

                if mnemonic == "PUSH":
                    if mnemonic_num == 0:
                        print(Node(mnemonic, "", mnemonic_num, stack_input_count), end="")
                    else:
                        print(
                            Node(
                                mnemonic,
                                "0x" + context.bytecode[pc + 1 : pc + 1 + mnemonic_num].hex(),
                                mnemonic_num,
                                stack_input_count,
                            ),
                            end="",
                        )
                else:
                    res = str(Node(mnemonic, input, mnemonic_num, stack_input_count))
                    if res[0] == "(":
                        print(res[1:-1], end="")
                    else:
                        print(res, end="")

                print()

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
                print("The maximum number of steps has been reached.")
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
            start_addresses.append(i + 1)

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
            elif mnemonic.startswith("DUP"):
                mnemonic_num = int(mnemonic[3:])
            elif mnemonic.startswith("SWAP"):
                mnemonic_num = int(mnemonic[4:])
            elif mnemonic.startswith("LOG"):
                mnemonic_num = int(mnemonic[3:])

            if mnemonic.startswith("PUSH"):
                instructions.append(
                    f"{pad(hex(pc), LOCATION_PAD_N)}: {mnemonic}  0x{context.bytecode[pc+1:pc+1+mnemonic_num].hex()}"
                )
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
        except Exception:
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
                graph += f"{block_id}({value}) --jump--> {next_block_id}\n"
            case ControlType.JUMPI:
                next_block_id = pad(hex(last_jump_to_address), LOCATION_PAD_N)
                graph += f"{block_id}({value}) --jump--> {next_block_id}\n"
                next_block_id = pad(hex(end_address + 1), LOCATION_PAD_N)
                graph += f"{block_id} --> {next_block_id}\n"
            case ControlType.END:
                next_block_id = "END"
                graph += f"{block_id}({value}) --> {next_block_id}\n"

    print(
        """<html lang="en">
    <head>
        <meta charset="utf-8" />
    </head>
    <body>"""
        + f"""<pre class="mermaid">

flowchart TB 
{graph}
    </pre>"""
        + """<script type="module">
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
    """
    )
