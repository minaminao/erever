from .opcodes import OPCODES


def assemble(mnemonics: str) -> bytes:
    mnemonics: list[str] = mnemonics.split(" ")
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
                assert len(arg) == mnemonic_num * 2, "Invalid PUSH argument"
                bytecode += arg

        i += 1

    return bytes.fromhex(bytecode)
