from collections import deque
from copy import deepcopy

from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .context import Context
from .node import Node
from .opcodes import OPCODES
from .symbolic_stack import SymbolicStack
from .utils import TAB_SIZE, UINT256_MAX, pad


def disassemble_symbolic(
    context: Context,
    entrypoint: int = 0x00,
    show_symbolic_stack: bool = False,
    max_steps: int = UINT256_MAX,
    hide_pc: bool = False,
    hide_instructions_with_no_stack_output: bool = False,
    show_opcodes: bool = False,
) -> None:
    class State:
        context: Context
        stack: SymbolicStack
        pc: int

        steps: int
        conditions: list[tuple[Node, int, bool]]
        jumped_from: int | None
        jumped: bool | None

        def __init__(self, context: Context, entrypoint: int = 0x00) -> None:
            self.context = context
            self.stack = SymbolicStack()
            self.pc = entrypoint

            self.steps = 0
            self.conditions = []  # [(condition, pc, is_met: bool)]
            self.jumped_from = None
            self.jumped = None

        def hash(self) -> int:
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

            input: list[Node] = [stack.pop() for _ in range(stack_input_count)]
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
                assert type(input[0].value) is int
                next_pc = input[0].value
            if mnemonic == "JUMPI" and input[0].type == "uint256":
                assert type(input[0].value) is int
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
