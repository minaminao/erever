import argparse

import toml

from .colors import colors
from .evm import *
from .opcodes import OPCODES
from .utils import *


def main():
    parser = argparse.ArgumentParser(description="EVM Reversing Tools", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--bytecode")
    parser.add_argument("-f", "--filename")

    parser.add_argument("--trace", action="store_true", default=False)
    parser.add_argument("--symbolic", action="store_true", default=False)
    parser.add_argument("--entrypoint", type=str, default="0")
    parser.add_argument("--show-symbolic-stack", action="store_true", default=False)
    parser.add_argument("-n", type=str, default=str(UINT256_MAX))
    # parser.add_argument("--rpc-url", type=str)

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

    args = parser.parse_args()

    args.entrypoint = parse_arg_param_to_int(args.entrypoint)
    args.n = parse_arg_param_to_int(args.n)
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
            parsed_toml = toml.load(open(args.filename))
            context = Context.from_dict(parsed_toml)
        else:
            bytecode = open(args.filename).read()
            context = Context.from_arg_params_with_bytecode(args, bytecode)

    if args.symbolic:
        disassemble_symbolic(context, args.trace, args.entrypoint, args.show_symbolic_stack, args.n)
    else:
        disassemble(context, args.trace, args.entrypoint, args.n)


def parse_arg_param_to_int(param):
    if param.startswith("0x"):
        return int(param, 16)
    else:
        return int(param)


def to_symbol(x):
    if type(x) is int:
        return pad_even(hex(x))
    else:
        return x


if __name__ == '__main__':
    main()
