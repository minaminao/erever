import copy
import sys
from dataclasses import dataclass

from Crypto.Hash import keccak
from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .context import Context
from .gas import GAS_CODE_WARM_COLD_DIFF, calculate_message_call_gas
from .memory import Memory
from .opcodes import OPCODES
from .precompiled_contracts import PRECOMPILED_CONTRACTS
from .stack import Stack
from .utils import SIGN_MASK, TAB_SIZE, UINT256_MAX, int256, is_invocation_mnemonic, pad, pad_even, uint256


@dataclass
class TraceLog:
    mnemonic_raw: str
    mnemonic: str
    input: list[int]
    stack_before_execution: Stack
    memory_before_execution: Memory
    gas: int
    depth: int

    def to_dict(self) -> dict[str, int | str | list[int]]:
        log_dict: dict[str, int | str | list[int]] = {}
        log_dict["mnemonic_raw"] = self.mnemonic_raw
        log_dict["mnemonic"] = self.mnemonic
        log_dict["input"] = self.input
        log_dict["stack_before_execution"] = self.stack_before_execution.stack
        log_dict["memory_before_execution"] = bytes(self.memory_before_execution.memory).hex()
        log_dict["gas"] = self.gas
        log_dict["depth"] = self.depth
        return log_dict


@dataclass
class DisassembleResult:
    last_jump_to_address: int | None
    disassemble_code: list[tuple[int, str | int]]
    trace_logs: list[TraceLog]
    success: bool
    return_data: bytes

    def to_dict(self) -> dict[str, int | None | list[tuple[int, str | int]] | list[dict[str, str | int | list[int]]]]:
        result_dict: dict[str, int | None | list[tuple[int, str | int]] | list[dict[str, str | int | list[int]]]] = {}
        result_dict["last_jump_to_address"] = self.last_jump_to_address
        result_dict["disassemble_code"] = self.disassemble_code
        result_dict["trace_logs"] = [log.to_dict() for log in self.trace_logs]
        return result_dict


class StaticCallError(Exception):
    pass


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
    rpc_url: str | None = None,
    return_trace_logs: bool = False,
) -> DisassembleResult:
    disassembled_code: list[tuple[int, str | int]] = []  # (pc, mnemonic)
    stack = Stack(ignore_stack_underflow=ignore_stack_underflow)
    memory = Memory()
    success = True
    return_data = b""

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages: str = ""

    pc = entrypoint
    last_jump_to_address = None
    trace_logs = []

    if context.chainid == 1 and context.address in PRECOMPILED_CONTRACTS:
        precompiled_contract_name, precompiled_contract_gas = PRECOMPILED_CONTRACTS[context.address]
        context.gas -= precompiled_contract_gas
        data_word_size = (len(context.calldata) + 31) // 32
        match precompiled_contract_name:
            case "ecRecover":
                assert False, "ecRecover is not supported"
            case "SHA2-256":
                context.gas -= 12 * data_word_size
                assert False, "SHA2-256 is not supported"
            case "RIPEMD-160":
                context.gas -= 120 * data_word_size
                assert False, "RIPEMD-160 is not supported"
            case "identity":
                context.gas -= 3 * data_word_size
                return_data = context.calldata
            case "modexp":
                assert False, "modexp is not supported"
            case "ecAdd":
                assert False, "ecAdd is not supported"
            case "ecMul":
                assert False, "ecMul is not supported"
            case "ecPairing":
                assert False, "ecPairing is not supported"
            case "blake2f":
                assert False, "blake2f is not supported"

    while pc < len(context.bytecode):
        instruction_message = ""
        next_pc = pc + 1
        value = context.bytecode[pc]
        if value in OPCODES:
            mnemonic_raw, stack_input_count, _stack_output_count, base_gas, _description, stack_input_names = OPCODES[
                value
            ]
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
            if return_trace_logs:
                copied_stack = copy.deepcopy(stack)
                copied_memory = copy.deepcopy(memory)

            input: list[int] = []
            for _ in range(stack_input_count):
                input.append(stack.pop())

            if return_trace_logs:
                trace_logs.append(
                    TraceLog(
                        mnemonic_raw,
                        mnemonic,
                        copy.deepcopy(input),
                        copied_stack,
                        copied_memory,
                        context.gas,
                        context.depth,
                    )
                )

            context.gas -= base_gas

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

            try:
                if context.static and mnemonic in [
                    "SSTORE",
                    "CREATE",
                    "CREATE2",
                    "CALLCODE",  # TODO
                    "SELFDESTRUCT",
                ]:
                    raise StaticCallError
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
                        a, exp = input
                        stack.push(uint256(a**exp))
                        exp_byte_size = (exp.bit_length() + 7) // 8
                        context.gas -= 50 * exp_byte_size
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
                        stack.push(UINT256_MAX ^ input[0])
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
                        input_data = memory.get_as_bytes(input[0], input[1])
                        if not silent:
                            instruction_message += f"\n{'input'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{input_data.hex()}"
                        k = keccak.new(digest_bits=256)
                        k.update(input_data)
                        GAS_KECCAK256_WORD = 6
                        context.gas -= GAS_KECCAK256_WORD * ((len(input_data) + 31) // 32)
                        stack.push(bytes_to_long(k.digest()))
                    case "ADDRESS":
                        stack.push(context.address)
                    case "BALANCE":
                        address = input[0]
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        stack.push(address)
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
                            context.gas -= memory.store(input[0], b"\x00" * size)
                        elif offset + size > len(context.calldata):
                            context.gas -= memory.store(
                                input[0], context.calldata[offset:] + b"\x00" * (offset + size - len(context.calldata))
                            )
                        else:
                            context.gas -= memory.store(input[0], context.calldata[offset : offset + size])
                        context.gas -= 3 * ((size + 31) // 32)
                    case "CODESIZE":
                        stack.push(len(context.bytecode))
                    case "CODECOPY":
                        # TODO: bound
                        memory.store(input[0], context.bytecode[input[1] : input[1] + input[2]])
                    case "GASPRICE":
                        stack.push(context.callvalue)
                    case "EXTCODESIZE":
                        address = input[0]
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        code = context.state.get_code(address)
                        stack.push(len(code))
                    case "EXTCODECOPY":
                        address = input[0]
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        assert False, "EXTCODECOPY is not supported"
                    case "RETURNDATASIZE":
                        stack.push(len(context.return_data))
                    case "RETURNDATACOPY":
                        dest_offset, offset, size = input
                        allocation_gas = memory.store(dest_offset, context.return_data[offset : offset + size])
                        context.gas -= allocation_gas
                        context.gas -= 3 * ((size + 31) // 32)
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
                        context.gas -= memory.store256(input[0], input[1])
                    case "MSTORE8":
                        memory.store8(input[0], input[1])
                    case "SLOAD":
                        value, gas = context.state.get_storage_at(context.address, input[0])
                        stack.push(value)
                        context.gas -= gas
                    case "SSTORE":
                        gas = context.state.set_storage_at(context.address, input[0], input[1])[0]
                        context.gas -= gas
                    case "JUMP":
                        assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST", "Invalid jump destination"
                        assert type(input[0]) is int
                        next_pc = input[0]
                        last_jump_to_address = input[0]
                    case "JUMPI":
                        assert OPCODES[context.bytecode[input[0]]][0] == "JUMPDEST", "Invalid jump destination"
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
                        offset = input[0]
                        size = input[1]
                        context.gas -= memory.extend(offset + size)
                        context.gas -= 8 * size
                    case "CREATE":
                        assert False, "CREATE is not supported"
                    case "CALL" | "STATICCALL":
                        if mnemonic == "CALL":
                            gas, address, value, args_offset, args_size, ret_offset, ret_size = input
                            if context.static and value > 0:
                                raise StaticCallError
                        elif mnemonic == "STATICCALL":
                            value = 0
                            gas, address, args_offset, args_size, ret_offset, ret_size = input

                        memory_cost = memory.extend(ret_offset + ret_size)
                        if value > 0:
                            extra_gas = 2300
                            context.gas -= 9000 - 2300  # TODO
                            # TODO: gas for empty account
                        else:
                            extra_gas = 0
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        code = context.state.get_code(address)
                        call_gas_cost = calculate_message_call_gas(value, gas, context.gas, memory_cost, extra_gas).cost
                        context.gas -= call_gas_cost
                        child_context = copy.deepcopy(context)
                        child_context.bytecode = code
                        child_context.gas = call_gas_cost
                        child_context.address = address
                        child_context.caller = context.address
                        child_context.callvalue = value
                        child_context.calldata = memory.get_as_bytes(args_offset, args_size)
                        child_context.return_data = b""
                        child_context.depth += 1
                        if mnemonic == "STATICCALL":
                            child_context.static = True

                        result = disassemble(
                            context=child_context,
                            trace=trace,
                            entrypoint=0,
                            max_steps=max_steps,
                            decode_stack=decode_stack,
                            ignore_stack_underflow=ignore_stack_underflow,
                            silent=silent,
                            hide_pc=hide_pc,
                            show_opcodes=show_opcodes,
                            hide_memory=hide_memory,
                            invocation_only=invocation_only,
                            rpc_url=rpc_url,
                            return_trace_logs=return_trace_logs,
                        )

                        if result.success:
                            context.gas += child_context.gas
                            context.state = child_context.state
                            result_return_data = result.return_data[:ret_size] + b"\x00" * max(
                                0, ret_size - len(result.return_data)
                            )
                            memory.store(ret_offset, result_return_data)
                            context.return_data = result.return_data
                        else:
                            context.state.original_storages = child_context.state.original_storages
                            context.state.codes = child_context.state.codes
                        context.steps = child_context.steps

                        stack.push(int(result.success))
                        trace_logs.extend(result.trace_logs)
                    case "CALLCODE":
                        assert False, "CALLCODE is not supported"
                    case "RETURN":
                        offset, size = input
                        if not silent:
                            instruction_message += (
                                f"\n{'return'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{memory.get_as_hex(offset, size)}"
                            )
                        return_data = memory.get_as_bytes(offset, size)
                        break_flag = True
                    case "DELEGATECALL":
                        assert False, "DELEGATECALL is not supported"
                    case "CREATE2":
                        assert False, "CREATE2 is not supported"
                    case "REVERT":
                        break_flag = True
                        success = False
                    case "INVALID":
                        break_flag = True
                        success = False
                    case "SELFDESTRUCT":
                        assert False, "SELFDESTRUCT is not supported"
                        break_flag = True
                    case _:
                        assert False, "Invalid opcode"
                        break_flag = True
                        success = False

            except StaticCallError as e:
                print("Static call revert", e, file=sys.stderr)
                break_flag = True
                success = False
            except Exception as e:
                print("Error", e, file=sys.stderr)
                break_flag = True
                success = False

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

        if not silent:
            if invocation_only:
                if is_invocation_mnemonic(mnemonic):
                    print(instruction_message)
            else:
                print(instruction_message)

        context.steps += 1
        if context.steps >= max_steps:
            break
        if break_flag:
            break
        pc = next_pc

    if not silent:
        print()
        if warning_messages != "":
            print(Colors.YELLOW + "WARNING:")
            print(warning_messages + Colors.ENDC)

    disassemble_result = DisassembleResult(
        last_jump_to_address, disassembled_code, trace_logs if trace and return_trace_logs else [], success, return_data
    )

    return disassemble_result
