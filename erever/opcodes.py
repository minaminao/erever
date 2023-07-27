OPCODES: dict[int, tuple[str, int, int, str, tuple]] = {
    # value: (mnemonic, stack input count, stack output count, description, stack input names)
    0x00: ("STOP", 0, 0, "Halts execution.", ()),
    0x01: ("ADD", 2, 1, "Addition operation.", ("a", "b")),
    0x02: ("MUL", 2, 1, "Multiplication operation.", ("a", "b")),
    0x03: ("SUB", 2, 1, "Subtraction operation.", ("a", "b")),
    0x04: ("DIV", 2, 1, "Integer division operation.", ("a", "b")),
    0x05: ("SDIV", 2, 1, "Signed integer division operation (truncated).", ("a", "b")),
    0x06: ("MOD", 2, 1, "Modulo remainder operation.", ("a", "b")),
    0x07: ("SMOD", 2, 1, "Signed modulo remainder operation.", ("a", "b")),
    0x08: ("ADDMOD", 3, 1, "Modulo addition operation.", ("a", "b", "mod")),
    0x09: ("MULMOD", 3, 1, "Modulo multiplication operation.", ("a", "b", "mod")),
    0x0A: ("EXP", 2, 1, "Exponential operation.", ("x", "exp")),
    0x0B: ("SIGNEXTEND", 2, 1, "Extend length of two's complement signed integer.", ("size", "x")),
    0x10: ("LT", 2, 1, "Less-than comparison.", ("a", "b")),
    0x11: ("GT", 2, 1, "Greater-than comparison.", ("a", "b")),
    0x12: ("SLT", 2, 1, "Signed less-than comparison.", ("a", "b")),
    0x13: ("SGT", 2, 1, "Signed greater-than comparison.", ("a", "b")),
    0x14: ("EQ", 2, 1, "Equality comparison.", ("a", "b")),
    0x15: ("ISZERO", 1, 1, "Simple not operator.", ("x",)),
    0x16: ("AND", 2, 1, "Bitwise AND operation.", ("a", "b")),
    0x17: ("OR", 2, 1, "Bitwise OR operation.", ("a", "b")),
    0x18: ("XOR", 2, 1, "Bitwise XOR operation.", ("a", "b")),
    0x19: ("NOT", 1, 1, "Bitwise NOT operation.", ("x",)),
    0x1A: ("BYTE", 2, 1, "Retrieve single byte from word.", ("i", "x")),
    0x1B: ("SHL", 2, 1, "Left shift operation.", ("shift", "x")),
    0x1C: ("SHR", 2, 1, "Logical right shift operation.", ("shift", "x")),
    0x1D: ("SAR", 2, 1, "Arithmetic (signed) right shift operation.", ("shift", "x")),
    0x20: ("KECCAK256", 2, 1, "Compute Keccak-256 hash.", ("offset", "size")),
    0x30: ("ADDRESS", 0, 1, "Get address of currently executing account.", ()),
    0x31: ("BALANCE", 1, 1, "Get balance of the given account.", ("addr",)),
    0x32: ("ORIGIN", 0, 1, "Get execution origination address.", ()),
    0x33: ("CALLER", 0, 1, "Get caller address.", ()),
    0x34: ("CALLVALUE", 0, 1, "Get deposited value by the instruction/transaction responsible for this execution.", ()),
    0x35: ("CALLDATALOAD", 1, 1, "Get input data of current environment.", ("offset",)),
    0x36: ("CALLDATASIZE", 0, 1, "Get size of input data in current environment.", ()),
    0x37: ("CALLDATACOPY", 3, 0, "Copy input data in current environment to memory.", ("memOffset", "offset", "size")),
    0x38: ("CODESIZE", 0, 1, "Get size of code running in current environment.", ()),
    0x39: ("CODECOPY", 3, 0, "Copy code running in current environment to memory.", ("memOffset", "offset", "size")),
    0x3A: ("GASPRICE", 0, 1, "Get price of gas in current environment.", ()),
    0x3B: ("EXTCODESIZE", 1, 1, "Get size of an account's code.", ("addr",)),
    0x3C: ("EXTCODECOPY", 4, 0, "Copy an account's code to memory.", ("addr", "memOffset", "offset", "size")),
    0x3D: ("RETURNDATASIZE", 0, 1, "Get size of output data from the previous call from the current environment.", ()),
    0x3E: (
        "RETURNDATACOPY",
        3,
        0,
        "Copy output data from the previous call to memory.",
        ("memOffset", "offset", "size"),
    ),
    0x3F: ("EXTCODEHASH", 1, 1, "Get hash of an account's code.", ("addr",)),
    0x40: ("BLOCKHASH", 1, 1, "Get the hash of one of the 256 most recent complete blocks.", ("number",)),
    0x41: ("COINBASE", 0, 1, "Get the current block's beneficiary address.", ()),
    0x42: ("TIMESTAMP", 0, 1, "Get the current block's timestamp.", ()),
    0x43: ("NUMBER", 0, 1, "Get the current block's number.", ()),
    0x44: ("DIFFICULTY", 0, 1, "Get the current block's difficulty.", ()),
    0x45: ("GASLIMIT", 0, 1, "Get the current block's gas limit.", ()),
    0x46: ("CHAINID", 0, 1, "Get the chain ID.", ()),
    0x47: ("SELFBALANCE", 0, 1, "Get balance of currently executing account.", ()),
    0x48: ("BASEFEE", 0, 1, "Get the base fee.", ()),
    0x50: ("POP", 1, 0, "Remove item from stack.", ("x",)),
    0x51: ("MLOAD", 1, 1, "Load word from memory.", ("offset",)),
    0x52: ("MSTORE", 2, 0, "Save word to memory.", ("offset", "x")),
    0x53: ("MSTORE8", 2, 0, "Save byte to memory.", ("offset", "x")),
    0x54: ("SLOAD", 1, 1, "Load word from storage.", ("key",)),
    0x55: ("SSTORE", 2, 0, "Save word to storage.", ("key", "x")),
    0x56: ("JUMP", 1, 0, "Alter the program counter.", ("pc",)),
    0x57: ("JUMPI", 2, 0, "Conditionally alter the program counter.", ("pc", "cond")),
    0x58: (
        "PC",
        0,
        1,
        "Get the value of the program counter prior to the increment corresponding to this instruction.",
        (),
    ),
    0x59: ("MSIZE", 0, 1, "Get the size of active memory in bytes.", ()),
    0x5A: (
        "GAS",
        0,
        1,
        "Get the amount of available gas, including the corresponding reduction for the cost of this instruction.",
        (),
    ),
    0x5B: ("JUMPDEST", 0, 0, "Mark a valid destination for jumps.", ()),
    0x5F: ("PUSH0", 0, 0, "Place 0x00 on stack.", ()),
    0x60: ("PUSH1", 0, 1, "Place 1 byte item on stack.", ()),
    0x61: ("PUSH2", 0, 1, "Place 2 byte item on stack.", ()),
    0x62: ("PUSH3", 0, 1, "Place 3 byte item on stack.", ()),
    0x63: ("PUSH4", 0, 1, "Place 4 byte item on stack.", ()),
    0x64: ("PUSH5", 0, 1, "Place 5 byte item on stack.", ()),
    0x65: ("PUSH6", 0, 1, "Place 6 byte item on stack.", ()),
    0x66: ("PUSH7", 0, 1, "Place 7 byte item on stack.", ()),
    0x67: ("PUSH8", 0, 1, "Place 8 byte item on stack.", ()),
    0x68: ("PUSH9", 0, 1, "Place 9 byte item on stack.", ()),
    0x69: ("PUSH10", 0, 1, "Place 10 byte item on stack.", ()),
    0x6A: ("PUSH11", 0, 1, "Place 11 byte item on stack.", ()),
    0x6B: ("PUSH12", 0, 1, "Place 12 byte item on stack.", ()),
    0x6C: ("PUSH13", 0, 1, "Place 13 byte item on stack.", ()),
    0x6D: ("PUSH14", 0, 1, "Place 14 byte item on stack.", ()),
    0x6E: ("PUSH15", 0, 1, "Place 15 byte item on stack.", ()),
    0x6F: ("PUSH16", 0, 1, "Place 16 byte item on stack.", ()),
    0x70: ("PUSH17", 0, 1, "Place 17 byte item on stack.", ()),
    0x71: ("PUSH18", 0, 1, "Place 18 byte item on stack.", ()),
    0x72: ("PUSH19", 0, 1, "Place 19 byte item on stack.", ()),
    0x73: ("PUSH20", 0, 1, "Place 20 byte item on stack.", ()),
    0x74: ("PUSH21", 0, 1, "Place 21 byte item on stack.", ()),
    0x75: ("PUSH22", 0, 1, "Place 22 byte item on stack.", ()),
    0x76: ("PUSH23", 0, 1, "Place 23 byte item on stack.", ()),
    0x77: ("PUSH24", 0, 1, "Place 24 byte item on stack.", ()),
    0x78: ("PUSH25", 0, 1, "Place 25 byte item on stack.", ()),
    0x79: ("PUSH26", 0, 1, "Place 26 byte item on stack.", ()),
    0x7A: ("PUSH27", 0, 1, "Place 27 byte item on stack.", ()),
    0x7B: ("PUSH28", 0, 1, "Place 28 byte item on stack.", ()),
    0x7C: ("PUSH29", 0, 1, "Place 29 byte item on stack.", ()),
    0x7D: ("PUSH30", 0, 1, "Place 30 byte item on stack.", ()),
    0x7E: ("PUSH31", 0, 1, "Place 31 byte item on stack.", ()),
    0x7F: ("PUSH32", 0, 1, "Place 32-byte (full word) item on stack.", ()),
    0x80: ("DUP1", 1, 2, "Duplicate 1st stack item.", ("x",)),
    0x81: ("DUP2", 2, 3, "Duplicate 2nd stack item.", ("x",)),
    0x82: ("DUP3", 3, 4, "Duplicate 3rd stack item.", ("x",)),
    0x83: ("DUP4", 4, 5, "Duplicate 4th stack item.", ("x",)),
    0x84: ("DUP5", 5, 6, "Duplicate 5th stack item.", ("x",)),
    0x85: ("DUP6", 6, 7, "Duplicate 6th stack item.", ("x",)),
    0x86: ("DUP7", 7, 8, "Duplicate 7th stack item.", ("x",)),
    0x87: ("DUP8", 8, 9, "Duplicate 8th stack item.", ("x",)),
    0x88: ("DUP9", 9, 10, "Duplicate 9th stack item.", ("x",)),
    0x89: ("DUP10", 10, 11, "Duplicate 10th stack item.", ("x",)),
    0x8A: ("DUP11", 11, 12, "Duplicate 11th stack item.", ("x",)),
    0x8B: ("DUP12", 12, 13, "Duplicate 12th stack item.", ("x",)),
    0x8C: ("DUP13", 13, 14, "Duplicate 13th stack item.", ("x",)),
    0x8D: ("DUP14", 14, 15, "Duplicate 14th stack item.", ("x",)),
    0x8E: ("DUP15", 15, 16, "Duplicate 15th stack item.", ("x",)),
    0x8F: ("DUP16", 16, 17, "Duplicate 16th stack item.", ("x",)),
    0x90: ("SWAP1", 2, 2, "Exchange 1st and 2nd stack items.", ("a", "b")),
    0x91: ("SWAP2", 3, 3, "Exchange 1st and 3rd stack items.", ("a", "b")),
    0x92: ("SWAP3", 4, 4, "Exchange 1st and 4th stack items.", ("a", "b")),
    0x93: ("SWAP4", 5, 5, "Exchange 1st and 5th stack items.", ("a", "b")),
    0x94: ("SWAP5", 6, 6, "Exchange 1st and 6th stack items.", ("a", "b")),
    0x95: ("SWAP6", 7, 7, "Exchange 1st and 7th stack items.", ("a", "b")),
    0x96: ("SWAP7", 8, 8, "Exchange 1st and 8th stack items.", ("a", "b")),
    0x97: ("SWAP8", 9, 9, "Exchange 1st and 9th stack items.", ("a", "b")),
    0x98: ("SWAP9", 10, 10, "Exchange 1st and 10th stack items.", ("a", "b")),
    0x99: ("SWAP10", 11, 11, "Exchange 1st and 11th stack items.", ("a", "b")),
    0x9A: ("SWAP11", 12, 12, "Exchange 1st and 12th stack items.", ("a", "b")),
    0x9B: ("SWAP12", 13, 13, "Exchange 1st and 13th stack items.", ("a", "b")),
    0x9C: ("SWAP13", 14, 14, "Exchange 1st and 14th stack items.", ("a", "b")),
    0x9D: ("SWAP14", 15, 15, "Exchange 1st and 15th stack items.", ("a", "b")),
    0x9E: ("SWAP15", 16, 16, "Exchange 1st and 16th stack items.", ("a", "b")),
    0x9F: ("SWAP16", 17, 17, "Exchange 1st and 17th stack items.", ("a", "b")),
    0xA0: ("LOG0", 2, 0, "Append log record with no topics.", ("offset", "size")),
    0xA1: ("LOG1", 3, 0, "Append log record with one topic.", ("offset", "size", "topic1")),
    0xA2: ("LOG2", 4, 0, "Append log record with two topics.", ("offset", "size", "topic1", "topic2")),
    0xA3: ("LOG3", 5, 0, "Append log record with three topics.", ("offset", "size", "topic1", "topic2", "topic3")),
    0xA4: (
        "LOG4",
        6,
        0,
        "Append log record with four topics.",
        ("offset", "size", "topic1", "topic2", "topic3", "topic4"),
    ),
    0xF0: ("CREATE", 3, 1, "Create a new account with associated code.", ("value", "offset", "size")),
    0xF1: (
        "CALL",
        7,
        1,
        "Message-call into an account.",
        ("gas", "addr", "value", "argsOffset", "argsSize", "retOffset", "retSize"),
    ),
    0xF2: (
        "CALLCODE",
        7,
        1,
        "Message-call into this account with an alternative account's code.",
        ("gas", "addr", "value", "argsOffset", "argsSize", "retOffset", "retSize"),
    ),
    0xF3: ("RETURN", 2, 0, "Halt execution returning output data.", ("offset", "size")),
    0xF4: (
        "DELEGATECALL",
        6,
        1,
        "Message-call into this account with an alternative account's code, but persisting the current values for sender and value.",
        ("gas", "addr", "argsOffset", "argsSize", "retOffset", "retSize"),
    ),
    0xF5: (
        "CREATE2",
        4,
        1,
        "Create a new account with associated code at a predictable address",
        ("value", "offset", "size", "salt"),
    ),
    0xFA: (
        "STATICCALL",
        6,
        1,
        "Static message-call into an account.",
        ("gas", "addr", "argsOffset", "argsSize", "retOffset", "retSize"),
    ),
    0xFD: (
        "REVERT",
        2,
        0,
        "Halt execution reverting state changes but returning data and remaining gas.",
        ("offset", "size"),
    ),
    0xFE: ("INVALID", 0, 0, "Designated invalid instruction.", ()),
    0xFF: ("SELFDESTRUCT", 1, 0, "Halt execution and register account for later deletion.", ("addr",)),
}
