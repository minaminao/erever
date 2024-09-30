OPCODES_EOF: dict[int, tuple[str, int, int, int, str, tuple[str, ...]]] = {
    # value: (mnemonic, stack input count, stack output count, base_gas, description, stack input names)
    0x00: ("STOP", 0, 0, 0, "Halts execution.", ()),
    0x01: ("ADD", 2, 1, 3, "Addition operation.", ("a", "b")),
    0x02: ("MUL", 2, 1, 5, "Multiplication operation.", ("a", "b")),
    0x03: ("SUB", 2, 1, 3, "Subtraction operation.", ("a", "b")),
    0x04: ("DIV", 2, 1, 5, "Integer division operation.", ("a", "b")),
    0x05: (
        "SDIV",
        2,
        1,
        5,
        "Signed integer division operation (truncated).",
        ("a", "b"),
    ),
    0x06: ("MOD", 2, 1, 5, "Modulo remainder operation.", ("a", "b")),
    0x07: ("SMOD", 2, 1, 5, "Signed modulo remainder operation.", ("a", "b")),
    0x08: ("ADDMOD", 3, 1, 8, "Modulo addition operation.", ("a", "b", "mod")),
    0x09: ("MULMOD", 3, 1, 8, "Modulo multiplication operation.", ("a", "b", "mod")),
    0x0A: ("EXP", 2, 1, 10, "Exponential operation.", ("x", "exp")),
    0x0B: (
        "SIGNEXTEND",
        2,
        1,
        5,
        "Extend length of two's complement signed integer.",
        ("size", "x"),
    ),
    0x10: ("LT", 2, 1, 3, "Less-than comparison.", ("a", "b")),
    0x11: ("GT", 2, 1, 3, "Greater-than comparison.", ("a", "b")),
    0x12: ("SLT", 2, 1, 3, "Signed less-than comparison.", ("a", "b")),
    0x13: ("SGT", 2, 1, 3, "Signed greater-than comparison.", ("a", "b")),
    0x14: ("EQ", 2, 1, 3, "Equality comparison.", ("a", "b")),
    0x15: ("ISZERO", 1, 1, 3, "Simple not operator.", ("x",)),
    0x16: ("AND", 2, 1, 3, "Bitwise AND operation.", ("a", "b")),
    0x17: ("OR", 2, 1, 3, "Bitwise OR operation.", ("a", "b")),
    0x18: ("XOR", 2, 1, 3, "Bitwise XOR operation.", ("a", "b")),
    0x19: ("NOT", 1, 1, 3, "Bitwise NOT operation.", ("x",)),
    0x1A: ("BYTE", 2, 1, 3, "Retrieve single byte from word.", ("i", "x")),
    0x1B: ("SHL", 2, 1, 3, "Left shift operation.", ("shift", "x")),
    0x1C: ("SHR", 2, 1, 3, "Logical right shift operation.", ("shift", "x")),
    0x1D: (
        "SAR",
        2,
        1,
        3,
        "Arithmetic (signed) right shift operation.",
        ("shift", "x"),
    ),
    0x20: ("KECCAK256", 2, 1, 30, "Compute Keccak-256 hash.", ("offset", "size")),
    0x30: ("ADDRESS", 0, 1, 2, "Get address of currently executing account.", ()),
    0x31: ("BALANCE", 1, 1, 100, "Get balance of the given account.", ("addr",)),
    0x32: ("ORIGIN", 0, 1, 2, "Get execution origination address.", ()),
    0x33: ("CALLER", 0, 1, 2, "Get caller address.", ()),
    0x34: (
        "CALLVALUE",
        0,
        1,
        2,
        "Get deposited value by the instruction/transaction responsible for this execution.",
        (),
    ),
    0x35: (
        "CALLDATALOAD",
        1,
        1,
        3,
        "Get input data of current environment.",
        ("offset",),
    ),
    0x36: (
        "CALLDATASIZE",
        0,
        1,
        2,
        "Get size of input data in current environment.",
        (),
    ),
    0x37: (
        "CALLDATACOPY",
        3,
        0,
        3,
        "Copy input data in current environment to memory.",
        ("memOffset", "offset", "size"),
    ),
    0x39: (
        "CODECOPY",
        3,
        0,
        3,
        "Copy code running in current environment to memory.",
        ("memOffset", "offset", "size"),
    ),
    0x3A: ("GASPRICE", 0, 1, 2, "Get price of gas in current environment.", ()),
    0x3D: (
        "RETURNDATASIZE",
        0,
        1,
        2,
        "Get size of output data from the previous call from the current environment.",
        (),
    ),
    0x3E: (
        "RETURNDATACOPY",
        3,
        0,
        3,
        "Copy output data from the previous call to memory.",
        ("memOffset", "offset", "size"),
    ),
    0x40: (
        "BLOCKHASH",
        1,
        1,
        20,
        "Get the hash of one of the 256 most recent complete blocks.",
        ("number",),
    ),
    0x41: ("COINBASE", 0, 1, 2, "Get the current block's beneficiary address.", ()),
    0x42: ("TIMESTAMP", 0, 1, 2, "Get the current block's timestamp.", ()),
    0x43: ("NUMBER", 0, 1, 2, "Get the current block's number.", ()),
    0x44: ("PREVRANDAO", 0, 1, 2, "Get the previous block's RANDAO mix.", ()),
    0x45: ("GASLIMIT", 0, 1, 2, "Get the current block's gas limit.", ()),
    0x46: ("CHAINID", 0, 1, 2, "Get the chain ID.", ()),
    0x47: ("SELFBALANCE", 0, 1, 5, "Get balance of currently executing account.", ()),
    0x48: ("BASEFEE", 0, 1, 2, "Get the base fee.", ()),
    0x49: ("BLOBHASH", 1, 1, 3, "Get versioned hashes", ("index",)),
    0x4A: ("BLOBBASEFEE", 0, 1, 2, "Returns the value of the blob base-fee of the current block", ()),
    0x50: ("POP", 1, 0, 2, "Remove item from stack.", ("x",)),
    0x51: ("MLOAD", 1, 1, 3, "Load word from memory.", ("offset",)),
    0x52: ("MSTORE", 2, 0, 3, "Save word to memory.", ("offset", "x")),
    0x53: ("MSTORE8", 2, 0, 3, "Save byte to memory.", ("offset", "x")),
    0x54: ("SLOAD", 1, 1, 100, "Load word from storage.", ("key",)),
    0x55: ("SSTORE", 2, 0, 100, "Save word to storage.", ("key", "x")),
    0x59: ("MSIZE", 0, 1, 2, "Get the size of active memory in bytes.", ()),
    0x5B: ("NOP", 0, 0, 1, "NOP", ()),
    0x5C: ("TLOAD", 1, 1, 100, "Load word from transient storage", ("key",)),
    0x5D: ("TSTORE", 2, 0, 100, "Save word to transient storage", ("key", "value")),
    0x5E: (
        "MCOPY",
        3,
        0,
        3,
        "Copy word from memory to memory.",
        ("destOffset", "offset", "size"),
    ),
    0x5F: ("PUSH0", 0, 0, 2, "Place 0x00 on stack.", ()),
    0x60: ("PUSH1", 0, 1, 3, "Place 1 byte item on stack.", ()),
    0x61: ("PUSH2", 0, 1, 3, "Place 2 byte item on stack.", ()),
    0x62: ("PUSH3", 0, 1, 3, "Place 3 byte item on stack.", ()),
    0x63: ("PUSH4", 0, 1, 3, "Place 4 byte item on stack.", ()),
    0x64: ("PUSH5", 0, 1, 3, "Place 5 byte item on stack.", ()),
    0x65: ("PUSH6", 0, 1, 3, "Place 6 byte item on stack.", ()),
    0x66: ("PUSH7", 0, 1, 3, "Place 7 byte item on stack.", ()),
    0x67: ("PUSH8", 0, 1, 3, "Place 8 byte item on stack.", ()),
    0x68: ("PUSH9", 0, 1, 3, "Place 9 byte item on stack.", ()),
    0x69: ("PUSH10", 0, 1, 3, "Place 10 byte item on stack.", ()),
    0x6A: ("PUSH11", 0, 1, 3, "Place 11 byte item on stack.", ()),
    0x6B: ("PUSH12", 0, 1, 3, "Place 12 byte item on stack.", ()),
    0x6C: ("PUSH13", 0, 1, 3, "Place 13 byte item on stack.", ()),
    0x6D: ("PUSH14", 0, 1, 3, "Place 14 byte item on stack.", ()),
    0x6E: ("PUSH15", 0, 1, 3, "Place 15 byte item on stack.", ()),
    0x6F: ("PUSH16", 0, 1, 3, "Place 16 byte item on stack.", ()),
    0x70: ("PUSH17", 0, 1, 3, "Place 17 byte item on stack.", ()),
    0x71: ("PUSH18", 0, 1, 3, "Place 18 byte item on stack.", ()),
    0x72: ("PUSH19", 0, 1, 3, "Place 19 byte item on stack.", ()),
    0x73: ("PUSH20", 0, 1, 3, "Place 20 byte item on stack.", ()),
    0x74: ("PUSH21", 0, 1, 3, "Place 21 byte item on stack.", ()),
    0x75: ("PUSH22", 0, 1, 3, "Place 22 byte item on stack.", ()),
    0x76: ("PUSH23", 0, 1, 3, "Place 23 byte item on stack.", ()),
    0x77: ("PUSH24", 0, 1, 3, "Place 24 byte item on stack.", ()),
    0x78: ("PUSH25", 0, 1, 3, "Place 25 byte item on stack.", ()),
    0x79: ("PUSH26", 0, 1, 3, "Place 26 byte item on stack.", ()),
    0x7A: ("PUSH27", 0, 1, 3, "Place 27 byte item on stack.", ()),
    0x7B: ("PUSH28", 0, 1, 3, "Place 28 byte item on stack.", ()),
    0x7C: ("PUSH29", 0, 1, 3, "Place 29 byte item on stack.", ()),
    0x7D: ("PUSH30", 0, 1, 3, "Place 30 byte item on stack.", ()),
    0x7E: ("PUSH31", 0, 1, 3, "Place 31 byte item on stack.", ()),
    0x7F: ("PUSH32", 0, 1, 3, "Place 32-byte (full word) item on stack.", ()),
    0x80: ("DUP1", 1, 2, 3, "Duplicate 1st stack item.", ("x",)),
    0x81: ("DUP2", 2, 3, 3, "Duplicate 2nd stack item.", ("x",)),
    0x82: ("DUP3", 3, 4, 3, "Duplicate 3rd stack item.", ("x",)),
    0x83: ("DUP4", 4, 5, 3, "Duplicate 4th stack item.", ("x",)),
    0x84: ("DUP5", 5, 6, 3, "Duplicate 5th stack item.", ("x",)),
    0x85: ("DUP6", 6, 7, 3, "Duplicate 6th stack item.", ("x",)),
    0x86: ("DUP7", 7, 8, 3, "Duplicate 7th stack item.", ("x",)),
    0x87: ("DUP8", 8, 9, 3, "Duplicate 8th stack item.", ("x",)),
    0x88: ("DUP9", 9, 10, 3, "Duplicate 9th stack item.", ("x",)),
    0x89: ("DUP10", 10, 11, 3, "Duplicate 10th stack item.", ("x",)),
    0x8A: ("DUP11", 11, 12, 3, "Duplicate 11th stack item.", ("x",)),
    0x8B: ("DUP12", 12, 13, 3, "Duplicate 12th stack item.", ("x",)),
    0x8C: ("DUP13", 13, 14, 3, "Duplicate 13th stack item.", ("x",)),
    0x8D: ("DUP14", 14, 15, 3, "Duplicate 14th stack item.", ("x",)),
    0x8E: ("DUP15", 15, 16, 3, "Duplicate 15th stack item.", ("x",)),
    0x8F: ("DUP16", 16, 17, 3, "Duplicate 16th stack item.", ("x",)),
    0x90: ("SWAP1", 2, 2, 3, "Exchange 1st and 2nd stack items.", ("a", "b")),
    0x91: ("SWAP2", 3, 3, 3, "Exchange 1st and 3rd stack items.", ("a", "b")),
    0x92: ("SWAP3", 4, 4, 3, "Exchange 1st and 4th stack items.", ("a", "b")),
    0x93: ("SWAP4", 5, 5, 3, "Exchange 1st and 5th stack items.", ("a", "b")),
    0x94: ("SWAP5", 6, 6, 3, "Exchange 1st and 6th stack items.", ("a", "b")),
    0x95: ("SWAP6", 7, 7, 3, "Exchange 1st and 7th stack items.", ("a", "b")),
    0x96: ("SWAP7", 8, 8, 3, "Exchange 1st and 8th stack items.", ("a", "b")),
    0x97: ("SWAP8", 9, 9, 3, "Exchange 1st and 9th stack items.", ("a", "b")),
    0x98: ("SWAP9", 10, 10, 3, "Exchange 1st and 10th stack items.", ("a", "b")),
    0x99: ("SWAP10", 11, 11, 3, "Exchange 1st and 11th stack items.", ("a", "b")),
    0x9A: ("SWAP11", 12, 12, 3, "Exchange 1st and 12th stack items.", ("a", "b")),
    0x9B: ("SWAP12", 13, 13, 3, "Exchange 1st and 13th stack items.", ("a", "b")),
    0x9C: ("SWAP13", 14, 14, 3, "Exchange 1st and 14th stack items.", ("a", "b")),
    0x9D: ("SWAP14", 15, 15, 3, "Exchange 1st and 15th stack items.", ("a", "b")),
    0x9E: ("SWAP15", 16, 16, 3, "Exchange 1st and 16th stack items.", ("a", "b")),
    0x9F: ("SWAP16", 17, 17, 3, "Exchange 1st and 17th stack items.", ("a", "b")),
    0xA0: ("LOG0", 2, 0, 375, "Append log record with no topics.", ("offset", "size")),
    0xA1: (
        "LOG1",
        3,
        0,
        750,
        "Append log record with one topic.",
        ("offset", "size", "topic1"),
    ),
    0xA2: (
        "LOG2",
        4,
        0,
        1125,
        "Append log record with two topics.",
        ("offset", "size", "topic1", "topic2"),
    ),
    0xA3: (
        "LOG3",
        5,
        0,
        1500,
        "Append log record with three topics.",
        ("offset", "size", "topic1", "topic2", "topic3"),
    ),
    0xA4: (
        "LOG4",
        6,
        0,
        1875,
        "Append log record with four topics.",
        ("offset", "size", "topic1", "topic2", "topic3", "topic4"),
    ),
    0xD0: ("DATALOAD", 1, 1, 4, "Load 32-byte word from data section of EOF container to the stack", ("offset",)),
    0xD1: (
        "DATALOADN",
        0,
        1,
        3,
        "Load 32-byte word from data section of EOF container at given offset to the stack",
        (),
    ),
    0xD2: ("DATASIZE", 0, 1, 2, "Push data section size to the stack", ()),
    0xD3: ("DATACOPY", 3, 0, 3, "Copy data section of EOF container to memory", ("memOffset", "offset", "size")),
    0xE0: ("RJUMP", 0, 0, 2, "Alter the program counter to relative offset", ()),
    0xE1: ("RJUMPI", 1, 0, 4, "Conditionally alter the program counter to relative offset", ("condition",)),
    0xE2: ("RJUMPV", 1, 0, 4, "Alter the program counter to a relative offset in jump table", ("case",)),
    0xE3: ("CALLF", 0, 0, 5, "Call into a function", ()),
    0xE4: ("RETF", 0, 0, 3, "Return from a function", ()),
    0xE5: ("JUMPF", 0, 0, 5, "Chaining function calls without adding a new return stack frame", ()),
    0xE6: ("DUPN", 0, 0, 3, "Duplicate the stack item at the top of the stack", ("x",)),
    0xE7: ("SWAPN", 0, 0, 3, "Swap the stack item with the top stack item", ("a", "b")),
    0xE8: ("EXCHANGE", 0, 0, 3, "Swap between the first and second nibbles of the stack item", ()),
    0xEC: (
        "EOFCREATE",
        4,
        1,
        32000,
        "Create a contract using EOF container at given index",
        ("value", "salt", "inputOffset", "inputSize"),
    ),
    0xEE: ("RETURNCONTRACT", 2, 0, 0, "Deploy container to an address", ("aux_data_offset", "aux_data_size")),
    0xF3: (
        "RETURN",
        2,
        0,
        0,
        "Halt execution returning output data.",
        ("offset", "size"),
    ),
    0xF7: ("RETURNDATALOAD", 1, 1, 3, "Push 32-byte word from the return data at offset onto the stack", ("offset",)),
    0xF8: (
        "EXTCALL",
        4,
        1,
        100,
        "Drop-in replacement for CALL instruction",
        ("target_address", "input_offset", "input_size", "value"),
    ),
    0xF9: (
        "EXTDELEGATECALL",
        3,
        1,
        100,
        "Drop-in replacement for DELEGATECALL instruction",
        ("targetAddress", "inputOffset", "inputSize"),
    ),
    0xFB: (
        "EXTSTATICCALL",
        3,
        1,
        100,
        "Drop-in replacement for STATICCALL instruction",
        ("targetAddress", "inputOffset", "inputSize"),
    ),
    0xFD: (
        "REVERT",
        2,
        0,
        0,
        "Halt execution reverting state changes but returning data and remaining gas.",
        ("offset", "size"),
    ),
    0xFE: ("INVALID", 0, 0, 0, "Designated invalid instruction.", ()),  # gas: NaN
}
