from .opcodes.cancun import OPCODES
from .opcodes.eof import OPCODES_EOF
from .utils.general import remove_comments


def assemble(mnemonics_str: str, eof: bool = False) -> bytes:
    mnemonics: list[str] = remove_comments(mnemonics_str).split()
    i = 0
    bytecode = ""
    if eof:
        mnemonic_to_opcode = {v[0]: opcode for opcode, v in OPCODES_EOF.items()}
    else:
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
        elif mnemonic_upper in ["EXCHANGE", "EOFCREATE", "RETURNCONTRACT"]:
            i += 1
            arg = mnemonics[i]
            if arg.startswith("0x"):
                arg = arg[2:]
            else:
                arg = hex(int(arg))[2:].zfill(2)
            assert len(arg) == 2, "Invalid EXCHANGE argument"
            bytecode += arg
        elif mnemonic_upper in ["DATALOADN", "RJUMP", "RJUMPI", "CALLF", "JUMPF"]:
            i += 1
            arg = mnemonics[i]
            if arg.startswith("0x"):
                arg = arg[2:]
            else:
                arg = hex(int(arg))[2:].zfill(4)
            assert len(arg) == 4, "Invalid RJUMPI argument"
            bytecode += arg

        i += 1

    return bytes.fromhex(bytecode)
