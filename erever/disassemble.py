import copy
import sys
from dataclasses import dataclass
from enum import Enum

from Crypto.Hash import SHA256, keccak
from Crypto.Util.number import bytes_to_long

from .data_structure.context import Context
from .data_structure.memory import Memory
from .data_structure.stack import Stack
from .eof import EOF, parse_eof_body, parse_eof_header
from .gas import GAS_CODE_WARM_COLD_DIFF, GAS_KECCAK256_WORD, calculate_message_call_gas
from .opcodes.cancun import OPCODES
from .opcodes.eof import OPCODES_EOF
from .precompiled_contracts.shanghai import PRECOMPILED_CONTRACTS
from .utils.colors import Colors
from .utils.general import (
    SIGN_MASK,
    TAB_SIZE,
    UINT256_MAX,
    compute_contract_address,
    compute_contract_address_by_eofcreate,
    int256,
    is_invocation_mnemonic,
    pad,
    pad_even,
    uint256,
)


@dataclass
class TraceLog:
    mnemonic_raw: str
    mnemonic: str
    input: list[int] | int
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


DisassembleCode = list[tuple[int, str, int | None]]
DisassembleResultDict = dict[
    str,
    int | None | DisassembleCode | list[dict[str, str | int | list[int]]] | list[int] | str,
]  # TODO


@dataclass
class DisassembleResult:
    last_jump_to_address: int | None
    disassemble_code: DisassembleCode
    trace_logs: list[TraceLog]
    success: bool
    return_data: bytes
    stack_after_execution: Stack
    memory_after_execution: Memory

    def to_dict(
        self,
    ) -> DisassembleResultDict:
        result_dict: DisassembleResultDict = {}
        result_dict["last_jump_to_address"] = self.last_jump_to_address
        result_dict["disassemble_code"] = self.disassemble_code
        result_dict["trace_logs"] = [log.to_dict() for log in self.trace_logs]
        result_dict["stack_after_execution"] = self.stack_after_execution.stack
        result_dict["memory_after_execution"] = bytes(self.memory_after_execution.memory).hex()
        return result_dict


class MemoryDisplay(Enum):
    ALWAYS = "always"
    ONCHANGE = "onchange"
    OFF = "off"

    def __str__(self) -> str:
        return self.value


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
    memory_display: MemoryDisplay = MemoryDisplay.OFF,
    memory_range: list[tuple[int, int]] | None = None,
    invocation_only: bool = False,
    return_trace_logs: bool = False,
) -> DisassembleResult:
    return_data = b""

    if context.chainid == 1 and context.address in PRECOMPILED_CONTRACTS:
        precompiled_contract_name, precompiled_contract_gas = PRECOMPILED_CONTRACTS[context.address]
        context.gas -= precompiled_contract_gas
        data_word_size = (len(context.calldata) + 31) // 32
        match precompiled_contract_name:
            case "ecRecover":
                assert False, "ecRecover is not supported"
            case "SHA2-256":
                context.gas -= 12 * data_word_size
                return_data = SHA256.new(data=context.calldata).digest()
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

        disassemble_result = DisassembleResult(
            None,
            [],
            [],
            True,
            return_data,
            Stack(),
            Memory(),
        )
    elif context.eof and context.bytecode[0:2] == b"\xef\x00":
        header, p = parse_eof_header(context.bytecode)
        eof, p = parse_eof_body(context.bytecode, header, p)
        context.eof = eof

        if trace:
            context.bytecode = eof.codes[0].code
            context.eof.return_stack = [(0, 0)]
            disassemble_code(
                context,
                trace,
                0,
                max_steps,
                decode_stack,
                ignore_stack_underflow,
                silent,
                hide_pc,
                show_opcodes,
                memory_display,
                memory_range,
                invocation_only,
                return_trace_logs,
            )
        else:
            for i, code in enumerate(eof.codes):
                print(f"Code {i}:")
                context.bytecode = code.code
                disassemble_code(
                    context,
                    trace,
                    0,
                    max_steps,
                    decode_stack,
                    ignore_stack_underflow,
                    silent,
                    hide_pc,
                    show_opcodes,
                    memory_display,
                    memory_range,
                    invocation_only,
                    return_trace_logs,
                )

        disassemble_result = DisassembleResult(
            None,
            [],
            [],
            True,
            b"",
            Stack(),
            Memory(),
        )
    else:
        disassemble_result = disassemble_code(
            context=context,
            trace=trace,
            entrypoint=entrypoint,
            max_steps=max_steps,
            decode_stack=decode_stack,
            ignore_stack_underflow=ignore_stack_underflow,
            silent=silent,
            hide_pc=hide_pc,
            show_opcodes=show_opcodes,
            memory_display=memory_display,
            memory_range=memory_range,
            invocation_only=invocation_only,
            return_trace_logs=return_trace_logs,
        )

    return disassemble_result


def disassemble_code(
    context: Context,
    trace: bool = False,
    entrypoint: int = 0x00,
    max_steps: int = UINT256_MAX,
    decode_stack: bool = False,
    ignore_stack_underflow: bool = False,
    silent: bool = False,
    hide_pc: bool = False,
    show_opcodes: bool = False,
    memory_display: MemoryDisplay = MemoryDisplay.OFF,
    memory_range: list[tuple[int, int]] | None = None,
    invocation_only: bool = False,
    return_trace_logs: bool = False,
) -> DisassembleResult:
    disassembled_code: DisassembleCode = []  # (pc, mnemonic, push_v)
    stack = Stack(ignore_stack_underflow=ignore_stack_underflow)
    memory = Memory()
    success = True
    return_data = b""
    opcodes = OPCODES_EOF if context.eof else OPCODES

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    warning_messages: str = ""

    last_jump_to_address = None
    trace_logs = []

    pc = entrypoint
    while pc < len(context.bytecode):
        instruction_message = ""
        next_pc = pc + 1
        value = context.bytecode[pc]
        if value in opcodes:
            (
                mnemonic_raw,
                stack_input_count,
                _stack_output_count,
                base_gas,
                _description,
                stack_input_names,
            ) = opcodes[value]
        else:
            mnemonic_raw = Colors.YELLOW + f"0x{value:02x} (?)" + Colors.ENDC
            stack_input_count = 0
            _stack_output_count = 0
            base_gas = 0
            _description = None
            stack_input_names = ()

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

        # separate instruction names from numerical values
        mnemonic = ""
        if mnemonic_raw.startswith("PUSH"):
            mnemonic_num = int(mnemonic_raw[4:])
            push_v = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + mnemonic_num])
            if not silent and mnemonic_num > 0 and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + mnemonic_num].hex()
            next_pc = pc + 1 + mnemonic_num
            mnemonic = mnemonic_raw[:4]
        elif mnemonic_raw.startswith("DUP") and mnemonic_raw != "DUPN":
            mnemonic_num = int(mnemonic_raw[3:])
            mnemonic = mnemonic_raw[:3]
        elif mnemonic_raw == "DUPN":
            mnemonic_num = context.bytecode[pc + 1] + 1
            mnemonic = mnemonic_raw[:3]
            next_pc = pc + 1 + 1
            stack_input_count = mnemonic_num
            if not silent and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + 1].hex()
        elif mnemonic_raw.startswith("SWAP") and mnemonic_raw != "SWAPN":
            mnemonic_num = int(mnemonic_raw[4:])
            mnemonic = mnemonic_raw[:4]
        elif mnemonic_raw == "SWAPN":
            mnemonic_num = context.bytecode[pc + 1] + 1
            mnemonic = mnemonic_raw[:4]
            next_pc = pc + 1 + 1
            stack_input_count = mnemonic_num + 1
            if not silent and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + 1].hex()
        elif mnemonic_raw.startswith("LOG"):
            mnemonic_num = int(mnemonic_raw[3:])
            mnemonic = mnemonic_raw[:3]
        elif mnemonic_raw in ["EXCHANGE", "EOFCREATE", "RETURNCONTRACT"]:
            v_1byte = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + 1])
            next_pc = pc + 1 + 1
            if not silent and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + 1].hex()
            mnemonic_num = 0
            mnemonic = mnemonic_raw
        elif mnemonic_raw in ["DATALOADN", "RJUMP", "RJUMPI", "CALLF", "JUMPF"]:
            v_2bytes = bytes_to_long(context.bytecode[pc + 1 : pc + 1 + 2])
            next_pc = pc + 1 + 2
            if not silent and not invocation_only:
                instruction_message += " 0x" + context.bytecode[pc + 1 : pc + 1 + 2].hex()
            mnemonic_num = 0
            mnemonic = mnemonic_raw
        else:
            mnemonic_num = 0
            mnemonic = mnemonic_raw
        assert mnemonic != ""

        if mnemonic == "PUSH":
            disassembled_code.append((pc, mnemonic_raw, push_v))
        elif mnemonic in ["DUPN", "SWAPN", "EXCHANGE", "EOFCREATE", "RETURNCONTRACT"]:
            disassembled_code.append((pc, mnemonic_raw, v_1byte))
        elif mnemonic in ["DATALOADN", "RJUMP", "RJUMPI", "CALLF", "JUMPF"]:
            disassembled_code.append((pc, mnemonic_raw, v_2bytes))
        else:
            disassembled_code.append((pc, mnemonic_raw, None))

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
                        copy.deepcopy(input) if mnemonic != "PUSH" else push_v,
                        copied_stack,
                        copied_memory,
                        context.gas,
                        context.depth,
                    )
                )

            context.gas -= base_gas

            if not silent and len(stack_input_names) > 0:
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
                        byte_num, value = input
                        if byte_num > 31:
                            stack.push(input[1])
                        else:
                            bits = (byte_num + 1) * 8
                            mask = (1 << bits) - 1
                            value &= mask
                            sign = value >> (bits - 1)
                            if sign:
                                stack.push((1 << 256) - ((1 << bits) - value))
                            else:
                                stack.push(value)
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
                            stack.push((1 << 256) + (int256(input[1]) >> input[0]))
                        else:
                            stack.push(input[1] >> input[0])
                    case "KECCAK256":
                        input_data = memory.get_as_bytes(input[0], input[1])
                        if not silent:
                            instruction_message += f"\n{'input'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{input_data.hex()}"
                        context.gas -= GAS_KECCAK256_WORD * ((len(input_data) + 31) // 32)
                        stack.push(bytes_to_long(keccak.new(digest_bits=256, data=input_data).digest()))
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
                                input[0],
                                context.calldata[offset:] + b"\x00" * (offset + size - len(context.calldata)),
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
                        address, mem_offset, offset, size = input
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        code = context.state.get_code(address)
                        # TODO: bounds, gas
                        context.gas -= memory.store(
                            mem_offset,
                            code[offset : offset + size] + b"\x00" * max(0, (offset + size - len(code))),
                        )
                    case "RETURNDATASIZE":
                        stack.push(len(context.return_data))
                    case "RETURNDATACOPY":
                        dest_offset, offset, size = input
                        allocation_gas = memory.store(dest_offset, context.return_data[offset : offset + size])
                        context.gas -= allocation_gas
                        context.gas -= 3 * ((size + 31) // 32)
                    case "EXTCODEHASH":
                        address = input[0]
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        # TODO: empty account
                        code = context.state.get_code(address)
                        if len(code) == 0:
                            codehash = 0
                        else:
                            codehash = bytes_to_long(keccak.new(digest_bits=256, data=code).digest())
                        stack.push(codehash)
                    case "BLOCKHASH":
                        assert False, "BLOCKHASH is not supported"
                    case "COINBASE":
                        stack.push(context.coinbase)
                    case "TIMESTAMP":
                        stack.push(context.timestamp)
                    case "NUMBER":
                        stack.push(context.number)
                    case "PREVRANDAO":  # TODO
                        stack.push(context.difficulty)
                    case "GASLIMIT":
                        stack.push(context.gaslimit)
                    case "CHAINID":
                        stack.push(context.chainid)
                    case "SELFBALANCE":
                        stack.push(context.selfbalance)
                    case "BASEFEE":
                        stack.push(context.basefee)
                    case "BLOBHASH":
                        assert False, "BLOBHASH is not supported"
                    case "BLOBBASEFEE":
                        assert False, "BLOBBASEFEE is not supported"
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
                        assert opcodes[context.bytecode[input[0]]][0] == "JUMPDEST", "Invalid jump destination"
                        assert isinstance(input[0], int)
                        next_pc = input[0]
                        last_jump_to_address = input[0]
                    case "JUMPI":
                        assert opcodes[context.bytecode[input[0]]][0] == "JUMPDEST", "Invalid jump destination"
                        assert isinstance(input[0], int)
                        if input[1] != 0:
                            next_pc = input[0]
                        last_jump_to_address = input[0]
                    case "PC":
                        stack.push(pc)
                    case "MSIZE":
                        stack.push(len(memory.memory))
                    case "GAS":
                        stack.push(context.gas)
                    case "JUMPDEST" | "NOP":
                        pass
                    case "TLOAD":
                        assert False, "TLOAD is not supported"
                    case "TSTORE":
                        assert False, "TSTORE is not supported"
                    case "MCOPY":
                        # TODO: strict
                        memory.store(input[0], memory.get_as_bytes(input[1], input[2]))
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
                    case "DATALOAD":
                        offset = input[0]
                        assert isinstance(context.eof, EOF)
                        stack.push(context.eof.data.load(offset))
                    case "DATALOADN":
                        offset = v_2bytes
                        assert isinstance(context.eof, EOF)
                        stack.push(context.eof.data.load(offset))
                    case "DATASIZE":
                        assert isinstance(context.eof, EOF)
                        stack.push(len(context.eof.data.data))
                    case "DATACOPY":
                        mem_offset, offset, size = input
                        assert isinstance(context.eof, EOF)
                        memory.store(mem_offset, context.eof.data.get_as_bytes(offset, size))
                    case "RJUMP":
                        offset = v_2bytes if v_2bytes < 0x8000 else v_2bytes - 0x10000
                        next_pc = pc + 3 + offset
                        last_jump_to_address = offset
                    case "RJUMPI":
                        assert False, "RJUMPI is not supported"
                    case "RJUMPV":
                        assert False, "RJUMPV is not supported"
                    case "CALLF":
                        target_section_index = v_2bytes
                        assert isinstance(context.eof, EOF)
                        current_section_index = context.eof.return_stack[-1][0]
                        context.bytecode = context.eof.codes[target_section_index].code
                        disassemble_code(
                            context,
                            trace,
                            0,
                            max_steps,
                            decode_stack,
                            ignore_stack_underflow,
                            silent,
                            hide_pc,
                            show_opcodes,
                            memory_display,
                            memory_range,
                            invocation_only,
                            return_trace_logs,
                        )
                        context.bytecode = context.eof.codes[current_section_index].code
                    case "RETF":
                        break_flag = True
                    case "JUMPF":
                        assert isinstance(context.eof, EOF)
                        context.bytecode = context.eof.codes[target_section_index].code
                        disassemble_code(
                            context,
                            trace,
                            0,
                            max_steps,
                            decode_stack,
                            ignore_stack_underflow,
                            silent,
                            hide_pc,
                            show_opcodes,
                            memory_display,
                            memory_range,
                            invocation_only,
                            return_trace_logs,
                        )
                        break_flag = True
                    case "EXCHANGE":
                        assert False, "EXCHANGE is not supported"
                    case "EOFCREATE":
                        initcontainer_index = v_1byte
                        value, salt, input_offset, input_size = input
                        assert isinstance(context.eof, EOF)
                        initcontainer = context.eof.containers[initcontainer_index]
                        contract_address = compute_contract_address_by_eofcreate(
                            context.address, salt, initcontainer.container
                        )

                        child_context = copy.deepcopy(context)
                        child_context.bytecode = initcontainer.container
                        child_context.address = contract_address
                        child_context.caller = context.address
                        child_context.callvalue = value
                        child_context.calldata = memory.get_as_bytes(input_offset, input_size)
                        child_context.return_data = b""
                        child_context.depth += 1

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
                            memory_display=memory_display,
                            invocation_only=invocation_only,
                            return_trace_logs=return_trace_logs,
                        )

                    case "RETURNCONTRACT":
                        deploy_container_index = v_1byte
                        aux_data_offset, aux_data_size = input
                        assert isinstance(context.eof, EOF)
                        return_data = context.eof.containers[
                            deploy_container_index
                        ].container + context.eof.data.get_as_bytes(aux_data_offset, aux_data_size)
                        if not silent:
                            instruction_message += (
                                f"\n{'return'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{return_data.hex()}"
                            )
                        break_flag = True
                    case "CREATE":
                        value, offset, size = input
                        contract_address = compute_contract_address(context.address, 0)  # TODO: fix

                        child_context = copy.deepcopy(context)
                        child_context.bytecode = memory.get_as_bytes(offset, size)
                        # child_context.gas = call_gas_cost # TODO
                        child_context.address = contract_address
                        child_context.caller = context.address
                        child_context.callvalue = value
                        # child_context.calldata = memory.get_as_bytes(
                        #     args_offset, args_size
                        # )
                        child_context.calldata = b""
                        child_context.return_data = b""
                        child_context.depth += 1

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
                            memory_display=memory_display,
                            invocation_only=invocation_only,
                            return_trace_logs=return_trace_logs,
                        )

                        if result.success:
                            context.gas += child_context.gas
                            context.state = child_context.state
                            # result_return_data = result.return_data[
                            #     :ret_size
                            # ] + b"\x00" * max(0, ret_size - len(result.return_data))
                            # memory.store(ret_offset, result_return_data)
                            # context.return_data = result.return_data
                            context.state.set_code(contract_address, result.return_data)
                        else:
                            context.state.original_storages = child_context.state.original_storages
                            context.state.codes = child_context.state.codes
                        context.steps = child_context.steps

                        stack.push(contract_address if result.success else 0)
                        trace_logs.extend(result.trace_logs)
                    case "CALL" | "STATICCALL" | "DELEGATECALL":
                        if mnemonic == "CALL":
                            (
                                gas,
                                address,
                                callvalue,
                                args_offset,
                                args_size,
                                ret_offset,
                                ret_size,
                            ) = input
                            if context.static and callvalue > 0:
                                raise StaticCallError
                        elif mnemonic == "STATICCALL":
                            callvalue = 0
                            (
                                gas,
                                address,
                                args_offset,
                                args_size,
                                ret_offset,
                                ret_size,
                            ) = input
                        elif mnemonic == "DELEGATECALL":
                            callvalue = context.callvalue
                            (
                                gas,
                                address,
                                args_offset,
                                args_size,
                                ret_offset,
                                ret_size,
                            ) = input
                            if context.static:
                                raise StaticCallError

                        memory_cost = memory.extend(ret_offset + ret_size)
                        if callvalue > 0:
                            extra_gas = 2300
                            context.gas -= 9000 - 2300  # TODO
                            # TODO: gas for empty account
                        else:
                            extra_gas = 0
                        if address not in context.state.address_access_set:
                            context.gas -= GAS_CODE_WARM_COLD_DIFF
                            context.state.address_access_set.add(address)
                        code = context.state.get_code(address)
                        call_gas_cost = calculate_message_call_gas(
                            callvalue, gas, context.gas, memory_cost, extra_gas
                        ).cost
                        context.gas -= call_gas_cost
                        child_context = copy.deepcopy(context)
                        child_context.bytecode = code
                        child_context.gas = call_gas_cost
                        child_context.address = address if mnemonic != "DELEGATECALL" else context.address
                        child_context.caller = context.address
                        child_context.callvalue = callvalue
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
                            memory_display=memory_display,
                            invocation_only=invocation_only,
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
                    case "CREATE2":
                        assert False, "CREATE2 is not supported"
                    case "RETURNDATALOAD":
                        assert False, "RETURNDATALOAD is not supported"
                    case "EXTCALL":
                        assert False, "EXTCALL is not supported"
                    case "EXTDELEGATECALL":
                        assert False, "EXTDELEGATECALL is not supported"
                    case "EXTSTATICCALL":
                        assert False, "EXTSTATICCALL is not supported"
                    case "REVERT":
                        offset, size = input
                        return_data = memory.get_as_bytes(offset, size)
                        return_data_hex = memory.get_as_hex(offset, size)
                        if not silent:
                            instruction_message += f"\n{'revert'.rjust(TAB_SIZE * 2)}{' ' * TAB_SIZE}{return_data_hex}"
                            if return_data_hex.startswith("08c379a0"):
                                # Error(strings)
                                arg_data = return_data[0x04:]
                                strings_offset = int(arg_data[:0x20].hex(), 16)
                                strings_size = int(
                                    arg_data[strings_offset : strings_offset + 0x20].hex(),
                                    16,
                                )
                                strings = arg_data[strings_offset + 0x20 : strings_offset + 0x20 + strings_size]
                                instruction_message += f"\n{' ' * (TAB_SIZE * 3)}Error(string): {strings.decode()}"
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

            if memory_display == MemoryDisplay.ALWAYS or (
                memory_display == MemoryDisplay.ONCHANGE
                and mnemonic
                in [
                    "MLOAD",
                    "MSTORE",
                    "MSTORE8",
                    "MCOPY",
                    "CALL",
                    "STATICCALL",
                    "CALLCODE",
                    "DELEGATECALL",
                    "CODECOPY",
                    "EXTCODECOPY",
                    "RETURNDATACOPY",
                    "CALLDATACOPY",
                    "LOG",
                    "CREATE",
                    "CREATE2",
                    "RETURN",
                    "REVERT",
                ]
            ):
                lines = memory.to_string(memory_range=memory_range)
                for i, line in enumerate(lines):
                    if i == 0:
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
        last_jump_to_address,
        disassembled_code,
        trace_logs if trace and return_trace_logs else [],
        success,
        return_data,
        stack,
        memory,
    )

    return disassemble_result
