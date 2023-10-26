import argparse

from .opcodes import OPCODES


def transpile(args: argparse.Namespace) -> None:
    mnemonics: list[str] = args.mnemonics.split(" ")
    i = 0
    bytecode = ""
    mnemonic_to_opcode = {v[0]: opcode for opcode, v in OPCODES.items()}
    while i < len(mnemonics):
        mnemonic = mnemonics[i]
        mnemonic_upper = mnemonic.upper()
        bytecode += hex(mnemonic_to_opcode[mnemonic_upper])[2:].zfill(2)

        if mnemonic_upper.startswith("PUSH"):
            mnemonic_num = int(mnemonic[4:])
            if mnemonic_num > 0:
                i += 1
                arg = mnemonics[i]
                if arg.startswith("0x"):
                    arg = arg[2:]
                else:
                    arg = hex(int(arg))[2:].zfill(mnemonic_num * 2)
                bytecode += arg

        i += 1

    print(bytecode)
