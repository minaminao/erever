import copy
import json
from dataclasses import dataclass

from Crypto.Hash import keccak
from Crypto.Util.number import bytes_to_long
from web3 import HTTPProvider, Web3

from .colors import Colors
from .context import Context
from .memory import Memory
from .opcodes import OPCODES
from .stack import Stack
from .utils import SIGN_MASK, TAB_SIZE, UINT256_MAX, int256, is_invocation_mnemonic, pad, pad_even, uint256


@dataclass
class TraceLog:
    mnemonic_raw: str
    mnemonic: str
    input: list[int]
    stack_after_execution: Stack

    def to_dict(self) -> dict[str, str | list[int]]:
        log_dict: dict[str, str | list[int]] = {}
        log_dict["mnemonic_raw"] = self.mnemonic_raw
        log_dict["mnemonic"] = self.mnemonic
        log_dict["input"] = self.input
        log_dict["stack_after_execution"] = self.stack_after_execution.stack
        return log_dict


@dataclass
class DisassembleResult:
    last_jump_to_address: int | None
    disassemble_code: list[tuple[int, str | int]]
    trace_logs: list[TraceLog]

    def to_dict(self) -> dict[str, int | None | list[tuple[int, str | int]] | list[dict[str, str | list[int]]]]:
        result_dict: dict[str, int | None | list[tuple[int, str | int]] | list[dict[str, str | list[int]]]] = {}
        result_dict["last_jump_to_address"] = self.last_jump_to_address
        result_dict["disassemble_code"] = self.disassemble_code
        result_dict["trace_logs"] = [log.to_dict() for log in self.trace_logs]
        return result_dict


def disassemble(
    context: Context,
    trace: bool = False,
    entrypoint: int = 0x00,
    max_steps: int = UINT256_MAX,
    decode_stack: bool = False,
    ignore_stack_underflow: bool = False,
    silent: bool = False,
    hide_pc: bool = False,
    show_opcodes: bool = False,
    hide_memory: bool = False,
    invocation_only: bool = False,
    output_json: bool = False,
    rpc_url: str | None = None,
) -> DisassembleResult:
    disassembled_code: list[tuple[int, str | int]] = []  # (pc, mnemonic)
    stack = Stack(ignore_stack_underflow=ignore_stack_underflow)
    memory = Memory()
    state = context.state
    return_trace_logs = output_json

    w3 = Web3(HTTPProvider(rpc_url)) if rpc_url is not None else None

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages: str = ""

    pc = entrypoint
    steps = 0
    last_jump_to_address = None
    trace_logs = []

    while pc < len(context.bytecode):
        instruction_message = ""
        next_pc = pc + 1
        value = context.bytecode[pc]
        if value in OPCODES:
            mnemonic_raw, stack_input_count, _stack_output_count, _description, stack_input_names = OPCODES[value]
        else:
            mnemonic_raw = Colors.YELLOW + f"0x{value:02x} (?)" + Colors.ENDC
            stack_input_count = 0
            _stack_output_count = 0
            _description = None

            warning_messages += f"The mnemonic for 0x{value:02x} in {pad(hex(pc), LOCATION_PAD_N)} is not found.\n"

        if not silent:
            if not hide_pc:
                instruction_message += f"{pad(hex(pc), LOCATION_PAD_N)}: "
            if show_opcodes:
                instruction_message += f"{Colors.GRAY}(0x{context.bytecode[pc:pc+1].hex()}){Colors.ENDC} "
            if mnemonic_raw in ["JUMP", "JUMPI"]:
                instruction_message += f"{Colors.CYAN}{Colors.BOLD}{mnemonic_raw}{Colors.ENDC}"
            elif mnemonic_raw == "JUMPDEST":
                instruction_message += f"{Colors.BLUE}{Colors.BOLD}{mnemonic_raw}{Colors.ENDC}"
            else:
                instruction_message += f"{Colors.BOLD}{mnemonic_raw}{Colors.ENDC}"

        disassembled_code.append((pc, mnemonic_raw))

        # separate instruction names from numerical values
        mnemonic = ""
        if mnemonic_raw.startswith("PUSH"):
            mnemonic_num = int(mnemonic_raw[4:])
            push_v = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + mnemonic_num])
            if not silent and mnemonic_num > 0 and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + mnemonic_num].hex()
            next_pc = pc + 1 + mnemonic_num
            mnemonic = mnemonic_raw[:4]
            disassembled_code.append((pc + 1, push_v))
        elif mnemonic_raw.startswith("DUP"):
            mnemonic_num = int(mnemonic_raw[3:])
            mnemonic = mnemonic_raw[:3]
        elif mnemonic_raw.startswith("SWAP"):
            mnemonic_num = int(mnemonic_raw[4:])
            mnemonic = mnemonic_raw[:4]
        elif mnemonic_raw.startswith("LOG"):
            mnemonic_num = int(mnemonic_raw[3:])
            mnemonic = mnemonic_raw[:3]
        else:
            mnemonic_num = 0
            mnemonic = mnemonic_raw
        assert mnemonic != ""

        break_flag = False

        if trace:
            input: list[int] = []
            for _ in range(stack_input_count):
                input.append(stack.pop())

            if not silent:
                if len(stack_input_names) > 0:
                    instruction_message += "("
                    if mnemonic == "DUP":
                        if mnemonic_num >= 2:
                            instruction_message += "..., "
                        instruction_message += f"{pad_even(hex(input[-1]))}"
                    elif mnemonic == "SWAP":
                        if mnemonic_num >= 2:
                            instruction_message += f"{pad_even(hex(input[0]))}, ..., {pad_even(hex(input[-1]))}"
                        else:
                            instruction_message += f"{pad_even(hex(input[0]))}, {pad_even(hex(input[-1]))}"
                    else:
                        for i, name in enumerate(stack_input_names):
                            if i > 0:
                                instruction_message += ", "
                            if name != "":
                                instruction_message += f"{name}:"
                            instruction_message += f"{pad_even(hex(input[i]))}"
                    instruction_message += ")"

            match mnemonic:
                case "STOP":
                    break_flag = True
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
                        instruction_message += f"\n{'input'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{bytes(memory.memory[input[0]:input[0]+input[1]]).hex()}"
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
                    if w3:
                        code = w3.eth.get_code(w3.to_checksum_address(pad(hex(input[0]), 40)))[2:]
                        stack.push(len(code))
                    else:
                        assert False, "EXTCODESIZE is not supported"
                        stack.push(0)
                case "EXTCODECOPY":
                    assert False, "EXTCODECOPY is not supported"
                case "RETURNDATASIZE":
                    assert False, "RETURNDATASIZE is not supported"
                    stack.push(0)
                case "RETURNDATACOPY":
                    assert False, "RETURNDATACOPY is not supported"
                case "EXTCODEHASH":
                    assert False, "EXTCODEHASH is not supported"
                case "BLOCKHASH":
                    assert False, "BLOCKHASH is not supported"
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
                    stack.push(state.get_storage_at(context.address, input[0]))
                case "SSTORE":
                    state.set_storage_at(context.address, input[0], input[1])
                case "JUMP":
                    assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST"
                    assert type(input[0]) is int
                    next_pc = input[0]
                    last_jump_to_address = input[0]
                case "JUMPI":
                    assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST"
                    assert type(input[0]) is int
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
                    assert False, "CREATE is not supported"
                case "CALL":
                    assert False, "CALL is not supported"
                    # TODO
                    stack.push(0xCA11)
                case "CALLCODE":
                    assert False, "CALLCODE is not supported"
                    # TODO
                    stack.push(0xCA11)
                case "RETURN":
                    if not silent:
                        instruction_message += f"\n{'return'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{memory.get_hex(input[0], input[0] + input[1])}"
                    break_flag = True
                case "DELEGATECALL":
                    assert False, "DELEGATECALL is not supported"
                    # TODO
                    stack.push(0xCA11)
                case "CREATE2":
                    assert False, "CREATE2 is not supported"
                case "STATICCALL":
                    assert False, "STATICCALL is not supported"
                case "REVERT":
                    break_flag = True
                case "INVALID":
                    break_flag = True
                case "SELFDESTRUCT":
                    break_flag = True

        if trace and return_trace_logs:
            trace_logs.append(TraceLog(mnemonic_raw, mnemonic, input, copy.deepcopy(stack)))

        if trace and not silent:
            instruction_message += f"\n{'stack'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{stack.to_string()}"
            if decode_stack:
                instruction_message += f"\n{' ' * (TAB_SIZE * 3)}{stack.to_string_with_decode()}"

            if not hide_memory:
                lines = memory.to_string()
                for pc, line in enumerate(lines):
                    if pc == 0:
                        instruction_message += f"\n{'memory'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}"
                    else:
                        instruction_message += f"\n{' ' * (TAB_SIZE * 3)}"
                    instruction_message += f"{line}"

        if not silent and not output_json:
            if invocation_only:
                if is_invocation_mnemonic(mnemonic):
                    print(instruction_message)
            else:
                print(instruction_message)

        steps += 1
        if steps >= max_steps:
            break
        if break_flag:
            break
        pc = next_pc

    if not silent and not output_json:
        print()
        if warning_messages != "":
            print(Colors.YELLOW + "WARNING:")
            print(warning_messages + Colors.ENDC)

    disassemble_result = DisassembleResult(
        last_jump_to_address, disassembled_code, trace_logs if trace and return_trace_logs else []
    )

    if not silent and output_json:
        print(json.dumps(disassemble_result.to_dict()))

    return disassemble_result
