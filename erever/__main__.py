import argparse
import json
import os
import sys
import tomllib

from .context import Context
from .disassemble import disassemble
from .disassemble_mermaid import disassemble_mermaid
from .disassemble_symbolic import disassemble_symbolic
from .find_gadgets import find_gadgets
from .utils import UINT256_MAX


def command_disassemble(args: argparse.Namespace, context: Context) -> None:
    disassemble(
        context,
        False,
        args.entrypoint,
        args.max_steps,
        args.decode_stack,
        hide_pc=args.hide_pc,
        show_opcodes=args.show_opcodes,
        hide_memory=args.hide_memory,
    )


def command_trace(args: argparse.Namespace, context: Context) -> None:
    # tx gas
    context.gas -= 21000

    # tx data gas
    for byte in context.calldata:
        if byte == 0:
            context.gas -= 4
        else:
            context.gas -= 16

    result = disassemble(
        context,
        True,
        args.entrypoint,
        args.max_steps,
        args.decode_stack,
        hide_pc=args.hide_pc,
        show_opcodes=args.show_opcodes,
        hide_memory=args.hide_memory,
        invocation_only=args.invocation_only,
        silent=args.silent,
        rpc_url=args.rpc_url,
        return_trace_logs=args.return_trace_logs,
    )
    if args.output_json:
        print(json.dumps(result.to_dict()))


def command_symbolic_trace(args: argparse.Namespace, context: Context) -> None:
    disassemble_symbolic(
        context,
        args.entrypoint,
        args.show_symbolic_stack,
        args.max_steps,
        args.hide_pc,
        hide_instructions_with_no_stack_output=args.hide_instructions_with_no_stack_output,
        show_opcodes=args.show_opcodes,
    )


def command_mermaid(args: argparse.Namespace, context: Context) -> None:
    disassemble_mermaid(context, args.entrypoint, args.max_steps)


def command_gadget(args: argparse.Namespace, context: Context) -> None:
    find_gadgets(context, args.max_steps)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EVM Reversing Tools",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        usage="erever <COMMAND>",
    )
    subparsers = parser.add_subparsers()

    parser_disassemble = subparsers.add_parser("disassemble", aliases=["disas"], help="Disassemble the given bytecode")
    parser_disassemble.set_defaults(handler=command_disassemble)

    parser_trace = subparsers.add_parser("trace", help="Trace execution of the given bytecode")
    parser_trace.set_defaults(handler=command_trace)

    parser_symbolic_trace = subparsers.add_parser(
        "symbolic-trace", aliases=["symbolic"], help="Trace execution of the given bytecode symbolically"
    )
    parser_symbolic_trace.set_defaults(handler=command_symbolic_trace)

    parser_mermaid = subparsers.add_parser("mermaid", help="Generate the mermaid diagram for the given bytecode")
    parser_mermaid.set_defaults(handler=command_mermaid)

    parser_gadget = subparsers.add_parser("gadget", help="Find JOP gadgets in the given bytecode")
    parser_gadget.set_defaults(handler=command_gadget)

    def add_common_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("-b", "--bytecode")
        parser.add_argument("-f", "--filename")

        parser.add_argument("-c", "--contract-address")
        parser.add_argument("--tx")
        parser.add_argument("--rpc-url", type=str, default=os.getenv("EREVER_RPC_URL"))

        parser.add_argument("--entrypoint", type=str, default="0")
        parser.add_argument("--show-opcodes", action="store_true", default=False)
        parser.add_argument("--max-steps", type=str, default=str(UINT256_MAX))

        parser.add_argument("--hide-pc", action="store_true", default=False)
        parser.add_argument("--hide-memory", action="store_true", default=False)

        parser.add_argument("--address", type=str, default=str(Context.DEFAULT_ADDRESS))
        parser.add_argument("--balance", type=str, default=str(Context.DEFAULT_BALANCE))
        parser.add_argument("--origin", type=str, default=str(Context.DEFAULT_ORIGIN))
        parser.add_argument("--caller", type=str, default=str(Context.DEFAULT_CALLER))
        parser.add_argument("--callvalue", type=str, default=str(Context.DEFAULT_CALLVALUE))
        parser.add_argument("--calldata", type=str, default=Context.DEFAULT_CALLDATA_HEX)
        parser.add_argument("--gasprice", type=str, default=str(Context.DEFAULT_GASPRICE))
        parser.add_argument("--coinbase", type=str, default=str(Context.DEFAULT_COINBASE))
        parser.add_argument("--timestamp", type=str, default=str(Context.DEFAULT_TIMESTAMP))
        parser.add_argument("--number", type=str, default=str(Context.DEFAULT_NUMBER))
        parser.add_argument("--difficulty", type=str, default=str(Context.DEFAULT_DIFFICULTY))
        parser.add_argument("--gaslimit", type=str, default=str(Context.DEFAULT_GASLIMIT))
        parser.add_argument("--chainid", type=str, default=str(Context.DEFAULT_CHAINID))
        parser.add_argument("--selfbalance", type=str, default=str(Context.DEFAULT_SELFBALANCE))
        parser.add_argument("--basefee", type=str, default=str(Context.DEFAULT_BASEFEE))
        parser.add_argument("--gas", type=str, default=str(Context.DEFAULT_GAS))

    add_common_arguments(parser_disassemble)
    add_common_arguments(parser_trace)
    add_common_arguments(parser_symbolic_trace)
    add_common_arguments(parser_mermaid)
    add_common_arguments(parser_gadget)

    parser_disassemble.add_argument("--decode-stack", action="store_true", default=False)
    parser_trace.add_argument("--decode-stack", action="store_true", default=False)
    parser_trace.add_argument("--invocation-only", action="store_true", default=False)
    parser_trace.add_argument("--output-json", action="store_true", default=False)
    parser_trace.add_argument("--return-trace-logs", action="store_true", default=False)
    parser_trace.add_argument("--silent", action="store_true", default=False)
    parser_symbolic_trace.add_argument("--show-symbolic-stack", action="store_true", default=False)
    parser_symbolic_trace.add_argument("--hide-instructions-with-no-stack-output", action="store_true", default=False)

    args = parser.parse_args()

    args.entrypoint = parse_arg_param_to_int(args.entrypoint)
    args.max_steps = parse_arg_param_to_int(args.max_steps)
    args.address = parse_arg_param_to_int(args.address)
    args.balance = parse_arg_param_to_int(args.balance)
    args.origin = parse_arg_param_to_int(args.origin)
    args.caller = parse_arg_param_to_int(args.caller)
    args.callvalue = parse_arg_param_to_int(args.callvalue)
    args.gasprice = parse_arg_param_to_int(args.gasprice)
    args.coinbase = parse_arg_param_to_int(args.coinbase)
    args.timestamp = parse_arg_param_to_int(args.timestamp)
    args.number = parse_arg_param_to_int(args.number)
    args.difficulty = parse_arg_param_to_int(args.difficulty)
    args.gaslimit = parse_arg_param_to_int(args.gaslimit)
    args.chainid = parse_arg_param_to_int(args.chainid)
    args.selfbalance = parse_arg_param_to_int(args.selfbalance)
    args.basefee = parse_arg_param_to_int(args.basefee)
    args.gas = parse_arg_param_to_int(args.gas)

    if args.bytecode:
        context = Context.from_arg_params_with_bytecode(args, args.bytecode)
    elif args.filename:
        if args.filename.split(".")[-1] == "toml":
            parsed_toml = tomllib.load(open(args.filename, "rb"))
            context = Context.from_dict(parsed_toml)
        else:
            bytecode = open(args.filename).read()
            context = Context.from_arg_params_with_bytecode(args, bytecode)
    elif args.tx:
        context = Context.from_tx_hash(args)
    elif args.contract_address:
        context = Context.from_contract_address(args)
    else:
        parser.print_help(sys.stderr)
        exit(1)

    if hasattr(args, "handler"):
        args.handler(args, context)
    else:
        parser.print_help()
        exit(1)


def parse_arg_param_to_int(param: str) -> int:
    if param.startswith("0x"):
        return int(param, 16)
    else:
        return int(param)


if __name__ == "__main__":
    main()
