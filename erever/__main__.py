import argparse
import json
import os
import sys
import tomllib

from .assemble import assemble
from .colors import Colors
from .context import Context
from .disassemble import MemoryDisplay, disassemble
from .disassemble_mermaid import disassemble_mermaid
from .disassemble_symbolic import disassemble_symbolic
from .find_gadgets import find_gadgets
from .utils import UINT256_MAX


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(
        self,
        prog: str,
        indent_increment: int = 2,
        max_help_position: int = 53,
        width: int | None = None,
    ) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            (metavar,) = self._metavar_formatter(action, default)(1)
            return Colors.BOLD + metavar + Colors.ENDC
        else:
            if action.nargs != 0:
                return (
                    Colors.BOLD
                    + ", ".join(action.option_strings)
                    + Colors.ENDC
                    + " "
                    + self._format_args(action, action.dest.upper())
                )
            else:
                return Colors.BOLD + ", ".join(action.option_strings) + Colors.ENDC

    def _get_help_string(self, action: argparse.Action) -> str:
        help = action.help
        if help is None:
            help = ""

        if "%(default)" not in help:
            if action.default is not argparse.SUPPRESS:
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if action.option_strings or action.nargs in defaulting_nargs:
                    if action.default == str(UINT256_MAX):
                        help += " (default: (1 << 256) - 1)"
                    else:
                        help += " (default: %(default)s)"
        return help


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EVM Reversing Tools",
        formatter_class=CustomHelpFormatter,
    )
    subparsers = parser.add_subparsers()

    parser_disassemble = subparsers.add_parser(
        "disassemble",
        aliases=["disas"],
        help="Disassemble the given bytecode",
        formatter_class=CustomHelpFormatter,
    )
    parser_disassemble.set_defaults(handler=command_disassemble)

    parser_trace = subparsers.add_parser(
        "trace",
        help="Trace execution of the given bytecode",
        formatter_class=CustomHelpFormatter,
    )
    parser_trace.set_defaults(handler=command_trace)

    parser_symbolic_trace = subparsers.add_parser(
        "symbolic-trace",
        aliases=["symbolic"],
        help="Trace execution of the given bytecode symbolically",
        formatter_class=CustomHelpFormatter,
    )
    parser_symbolic_trace.set_defaults(handler=command_symbolic_trace)

    parser_mermaid = subparsers.add_parser(
        "mermaid",
        help="Generate the mermaid diagram for the given bytecode",
        formatter_class=CustomHelpFormatter,
    )
    parser_mermaid.set_defaults(handler=command_mermaid)

    parser_gadget = subparsers.add_parser(
        "gadget",
        help="Find JOP gadgets in the given bytecode",
        formatter_class=CustomHelpFormatter,
    )
    parser_gadget.set_defaults(handler=command_gadget)

    parser_assemble = subparsers.add_parser(
        "assemble",
        help="Assemble the given mnemonics to the bytecode",
        formatter_class=CustomHelpFormatter,
    )
    parser_assemble.set_defaults(handler=command_assemble)

    def add_common_arguments_for_data(
        parser: argparse.ArgumentParser,
    ) -> argparse._ArgumentGroup:
        group = parser.add_argument_group("data options")

        group.add_argument("-b", "--bytecode", help="Raw bytecode as hex string")
        group.add_argument("-f", "--filename", help="TOML or bytecode file")

        group.add_argument(
            "--rpc-url",
            type=str,
            default=os.getenv("EREVER_RPC_URL"),
            help="Fetch state from a remote endpoint instead of empty state",
        )
        group.add_argument("-c", "--contract-address", help="Requires --rpc-url")
        group.add_argument("--tx", help="Requires --rpc-url")

        group.add_argument(
            "--entrypoint",
            type=str,
            default="0",
            help="PC of entrypoint for disassembly/tracing",
        )
        group.add_argument(
            "--max-steps",
            type=str,
            default=str(UINT256_MAX),
            help="Maximum number of steps to disassemble/trace",
        )
        return group

    def add_common_arguments_for_display(
        parser: argparse.ArgumentParser,
    ) -> argparse._ArgumentGroup:
        group = parser.add_argument_group("display options")
        group.add_argument("--show-opcodes", action="store_true", default=False, help="Show opcodes")
        group.add_argument("--hide-pc", action="store_true", default=False, help="Hide PC")
        return group

    def add_common_arguments_for_constructing_context(
        parser: argparse.ArgumentParser,
    ) -> argparse._ArgumentGroup:
        group = parser.add_argument_group("context options")

        group.add_argument(
            "--address",
            type=str,
            default=str(Context.DEFAULT_ADDRESS),
            help="Address of the contract",
        )
        group.add_argument(
            "--origin",
            type=str,
            default=str(Context.DEFAULT_ORIGIN),
            help="Origin of the transaction",
        )
        group.add_argument(
            "--caller",
            type=str,
            default=str(Context.DEFAULT_CALLER),
            help="Caller of the transaction",
        )
        group.add_argument(
            "--callvalue",
            type=str,
            default=str(Context.DEFAULT_CALLVALUE),
            help="Call value of the transaction",
        )
        group.add_argument(
            "--calldata",
            type=str,
            default=Context.DEFAULT_CALLDATA.decode(),
            help="Call data of the transaction",
        )
        group.add_argument(
            "--gasprice",
            type=str,
            default=str(Context.DEFAULT_GASPRICE),
            help="Gas price of the transaction",
        )
        group.add_argument(
            "--coinbase",
            type=str,
            default=str(Context.DEFAULT_COINBASE),
            help="Coinbase of the block",
        )
        group.add_argument(
            "--timestamp",
            type=str,
            default=str(Context.DEFAULT_TIMESTAMP),
            help="Timestamp of the block",
        )
        group.add_argument(
            "--number",
            type=str,
            default=str(Context.DEFAULT_NUMBER),
            help="Number of the block",
        )
        group.add_argument(
            "--difficulty",
            type=str,
            default=str(Context.DEFAULT_DIFFICULTY),
            help="Difficulty of the block",
        )
        group.add_argument(
            "--gaslimit",
            type=str,
            default=str(Context.DEFAULT_GASLIMIT),
            help="Gas limit of the block",
        )
        group.add_argument(
            "--chainid",
            type=str,
            default=str(Context.DEFAULT_CHAINID),
            help="Chain ID of the block",
        )
        group.add_argument(
            "--selfbalance",
            type=str,
            default=str(Context.DEFAULT_SELFBALANCE),
            help="Balance of the contract",
        )
        group.add_argument(
            "--basefee",
            type=str,
            default=str(Context.DEFAULT_BASEFEE),
            help="Base fee of the block",
        )
        group.add_argument(
            "--gas",
            type=str,
            default=str(Context.DEFAULT_GAS),
            help="Gas of the transaction",
        )
        return group

    add_common_arguments_for_data(parser_disassemble)
    add_common_arguments_for_data(parser_trace)
    add_common_arguments_for_data(parser_symbolic_trace)
    add_common_arguments_for_data(parser_mermaid)
    add_common_arguments_for_data(parser_gadget)
    add_common_arguments_for_display(parser_disassemble)
    trace_display_group = add_common_arguments_for_display(parser_trace)
    symbolic_trace_display_group = add_common_arguments_for_display(parser_symbolic_trace)
    add_common_arguments_for_display(parser_mermaid)
    add_common_arguments_for_display(parser_gadget)
    add_common_arguments_for_constructing_context(parser_trace)
    add_common_arguments_for_constructing_context(parser_symbolic_trace)
    add_common_arguments_for_constructing_context(parser_mermaid)
    add_common_arguments_for_constructing_context(parser_gadget)

    trace_display_group.add_argument("--decode-stack", action="store_true", default=False, help="Decode stack items")
    trace_display_group.add_argument(
        "--invocation-only",
        action="store_true",
        default=False,
        help="Display only invocation",
    )
    trace_display_group.add_argument("--output-json", action="store_true", default=False, help="Output trace as JSON")
    trace_display_group.add_argument(
        "--return-trace-logs",
        action="store_true",
        default=False,
        help="Return trace logs",
    )
    trace_display_group.add_argument("--silent", action="store_true", default=False, help="Don't print anything")
    trace_display_group.add_argument(
        "--memory-display",
        type=MemoryDisplay,
        choices=list(MemoryDisplay),
        default=MemoryDisplay.ONCHANGE,
        help="Specify when to display memory",
    )
    trace_display_group.add_argument(
        "--memory-range",
        nargs=2,
        action="append",
        type=str,
        metavar=("START", "END"),
        help="Specify memory ranges [START, END). Not applicable to subcontexts. Use multiple times for multiple ranges.",
    )
    symbolic_trace_display_group.add_argument(
        "--show-symbolic-stack",
        action="store_true",
        default=False,
        help="Show symbolic stack items",
    )
    symbolic_trace_display_group.add_argument(
        "--hide-instructions-with-no-stack-output",
        action="store_true",
        default=False,
        help="Hide instructions which do not output to the stack",
    )
    parser_assemble.add_argument("mnemonics", metavar="MNEMONICS", type=str, help="Mnemonics to assemble")

    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        exit(1)

    if args.handler == command_assemble:
        args.handler(args)
    else:
        args.rpc_url = args.rpc_url

        args.entrypoint = parse_arg_param_to_int(args.entrypoint)
        args.max_steps = parse_arg_param_to_int(args.max_steps)

        args.calldata = args.calldata if hasattr(args, "calldata") else ""
        args.address = parse_arg_param_to_int(args.address) if hasattr(args, "address") else None
        args.balance = parse_arg_param_to_int(args.balance) if hasattr(args, "balance") else None
        args.origin = parse_arg_param_to_int(args.origin) if hasattr(args, "origin") else None
        args.caller = parse_arg_param_to_int(args.caller) if hasattr(args, "caller") else None
        args.callvalue = parse_arg_param_to_int(args.callvalue) if hasattr(args, "callvalue") else None
        args.gasprice = parse_arg_param_to_int(args.gasprice) if hasattr(args, "gasprice") else None
        args.coinbase = parse_arg_param_to_int(args.coinbase) if hasattr(args, "coinbase") else None
        args.timestamp = parse_arg_param_to_int(args.timestamp) if hasattr(args, "timestamp") else None
        args.number = parse_arg_param_to_int(args.number) if hasattr(args, "number") else None
        args.difficulty = parse_arg_param_to_int(args.difficulty) if hasattr(args, "difficulty") else None
        args.gaslimit = parse_arg_param_to_int(args.gaslimit) if hasattr(args, "gaslimit") else None
        args.chainid = parse_arg_param_to_int(args.chainid) if hasattr(args, "chainid") else None
        args.selfbalance = parse_arg_param_to_int(args.selfbalance) if hasattr(args, "selfbalance") else None
        args.basefee = parse_arg_param_to_int(args.basefee) if hasattr(args, "basefee") else None
        args.gas = parse_arg_param_to_int(args.gas) if hasattr(args, "gas") else None
        args.memory_range = (
            [tuple([parse_arg_param_to_int(x) for x in y]) for y in args.memory_range]
            if hasattr(args, "memory_range") and args.memory_range is not None
            else None
        )

        if args.bytecode:
            context = Context.from_arg_params_with_bytecode(args, args.bytecode)
        elif args.filename:
            if args.filename.split(".")[-1] == "toml":
                parsed_toml = tomllib.load(open(args.filename, "rb"))
                if "bytecode" in parsed_toml:
                    parsed_toml["bytecode"] = bytes.fromhex(parsed_toml["bytecode"].replace("0x", "").replace(" ", ""))
                if "calldata" in parsed_toml:
                    parsed_toml["calldata"] = bytes.fromhex(parsed_toml["calldata"].replace("0x", "").replace(" ", ""))
                if "state" in parsed_toml:
                    parsed_toml["state_dict"] = parsed_toml["state"]
                    del parsed_toml["state"]
                context = Context(**parsed_toml)
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

        args.handler(args, context)


def command_disassemble(args: argparse.Namespace, context: Context) -> None:
    disassemble(
        context,
        trace=False,
        entrypoint=args.entrypoint,
        max_steps=args.max_steps,
        hide_pc=args.hide_pc,
        show_opcodes=args.show_opcodes,
    )

    # TODO: enable
    # inspect_cbor(context.bytecode)


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
        trace=True,
        entrypoint=args.entrypoint,
        max_steps=args.max_steps,
        decode_stack=args.decode_stack,
        hide_pc=args.hide_pc,
        show_opcodes=args.show_opcodes,
        memory_display=args.memory_display,
        invocation_only=args.invocation_only,
        silent=args.silent,
        return_trace_logs=args.return_trace_logs,
        memory_range=args.memory_range,
    )
    if args.output_json:
        print(json.dumps(result.to_dict()))


def command_symbolic_trace(args: argparse.Namespace, context: Context) -> None:
    disassemble_symbolic(
        context,
        entrypoint=args.entrypoint,
        show_symbolic_stack=args.show_symbolic_stack,
        max_steps=args.max_steps,
        hide_pc=args.hide_pc,
        hide_instructions_with_no_stack_output=args.hide_instructions_with_no_stack_output,
        show_opcodes=args.show_opcodes,
    )


def command_mermaid(args: argparse.Namespace, context: Context) -> None:
    disassemble_mermaid(context, args.entrypoint, args.max_steps)


def command_gadget(args: argparse.Namespace, context: Context) -> None:
    find_gadgets(context, args.max_steps)


def command_assemble(args: argparse.Namespace) -> None:
    bytecode = assemble(args.mnemonics)
    print(bytecode.hex())


def parse_arg_param_to_int(param: str) -> int:
    if param.startswith("0x"):
        return int(param, 16)
    else:
        return int(param)


if __name__ == "__main__":
    main()
