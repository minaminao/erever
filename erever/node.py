from .colors import Colors
from .utils import pad_even

NodeValue = str | int | list["Node"]


class Node:
    type: str
    value: NodeValue

    mnemonic_num: int | None
    input_count: int | None

    def __init__(
        self,
        type_: str,
        value: NodeValue,
        mnemonic_num: int | None = None,
        input_count: int | None = None,
    ) -> None:
        self.type = type_
        self.value = value

        self.mnemonic_num = mnemonic_num
        self.input_count = input_count

    @staticmethod
    def unwrap(s: "str | int | Node") -> str:
        s = str(s)
        return s[1:-1] if s[0] == "(" and s[-1] == ")" else s

    def evaluate(self) -> str:
        if self.type != "uint256" and self.type != "var":
            if self.type == "EQ":
                assert isinstance(self.value, list)
                if self.value[0].type == "uint256" and self.value[1].type == "uint256":
                    return str(self.value[0].value == self.value[1].value).lower()
        return ""

    def __repr__(self) -> str:
        if self.type == "uint256":
            assert isinstance(self.value, int), f"{self.type} {type(self.value)} {self.value}"
            return f"{pad_even(hex(self.value))}"
        elif self.type == "var":
            assert isinstance(self.value, str), f"{self.type} {type(self.value)} {self.value}"
            return self.value
        else:
            assert isinstance(self.value, list), f"{self.type} {type(self.value)} {self.value}"
            match self.type:
                # case "STOP":
                case "ADD":
                    return f"({self.value[0]} + {self.value[1]})"
                case "MUL":
                    return f"({self.value[0]} * {self.value[1]})"
                case "SUB":
                    return f"({self.value[0]} - {self.value[1]})"
                case "DIV":
                    return f"({self.value[0]} / {self.value[1]})"
                case "SDIV":
                    return f"(int256({Node.unwrap(self.value[0])}) / int256({Node.unwrap(self.value[1])}))"
                case "MOD":
                    return f"({self.value[0]} % {self.value[1]})"
                case "SMOD":
                    return f"(int256({Node.unwrap(self.value[0])}) % int256({Node.unwrap(self.value[1])}))"
                case "ADDMOD":
                    return f"(({self.value[0]} + {self.value[1]}) % {self.value[2]})"
                case "MULMOD":
                    return f"(({self.value[0]} * {self.value[1]}) % {self.value[2]})"
                case "EXP":
                    return f"({self.value[0]} ** {self.value[1]})"
                # case "SIGNEXTEND":
                case "LT":
                    return f"({self.value[0]} < {self.value[1]})"
                case "GT":
                    return f"({self.value[0]} > {self.value[1]})"
                case "SLT":
                    return f"(int256({Node.unwrap(self.value[0])}) < int256({Node.unwrap(self.value[1])}))"
                case "SGT":
                    return f"(int256({Node.unwrap(self.value[0])}) > int256({Node.unwrap(self.value[1])}))"
                case "EQ":
                    return f"({self.value[0]} == {self.value[1]})"
                # case "ISZERO":
                case "AND":
                    return f"({self.value[0]} & {self.value[1]})"
                case "OR":
                    return f"({self.value[0]} | {self.value[1]})"
                case "XOR":
                    return f"({self.value[0]} ^ {self.value[1]})"
                # case "NOT":
                # case "BYTE":
                case "SHL":
                    return f"({self.value[1]} << {self.value[0]})"
                case "SHR":
                    return f"({self.value[1]} >> {self.value[0]})"
                case "SAR":
                    return f"(int256({Node.unwrap(self.value[1])}) >> {self.value[0]})"
                # case "KECCAK256":
                # case "ADDRESS":
                # case "BALANCE":
                # case "ORIGIN":
                # case "CALLER":
                # case "CALLVALUE":
                # case "CALLDATALOAD":
                # case "CALLDATASIZE":
                # case "CALLDATACOPY":
                # case "CODESIZE":
                # case "CODECOPY":
                # case "GASPRICE":
                # case "EXTCODESIZE":
                # case "EXTCODECOPY":
                # case "RETURNDATASIZE":
                # case "RETURNDATACOPY":
                # case "EXTCODEHASH":
                # case "BLOCKHASH":
                # case "COINBASE":
                # case "TIMESTAMP":
                # case "NUMBER":
                # case "PREVRANDAO":
                # case "GASLIMIT":
                # case "CHAINID":
                # case "SELFBALANCE":
                # case "BASEFEE":
                case "POP":
                    return f"{Colors.GRAY}{Colors.BOLD}{self.type}{Colors.ENDC}{Colors.GRAY}(){Colors.ENDC} # {Node.unwrap(self.value[0])}"
                # case "MLOAD":
                # case "MSTORE":
                # case "MSTORE8":
                # case "SLOAD":
                # case "SSTORE":
                case "JUMP":
                    return f"{Colors.CYAN}{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])})"
                case "JUMPI":
                    return f"{Colors.CYAN}{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])}, {Node.unwrap(self.value[1])})"
                # case "PC":
                # case "MSIZE":
                # case "GAS":
                case "JUMPDEST":
                    return f"{Colors.BLUE}{Colors.BOLD}{self.type}{Colors.ENDC}{Colors.BLUE}(){Colors.ENDC}"
                case "PUSH":
                    if self.mnemonic_num == 0:
                        return f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}"
                    else:
                        return f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}({self.value[0]})"
                case "DUP":
                    ret = f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}() # "
                    assert isinstance(self.mnemonic_num, int)
                    if self.mnemonic_num >= 2:
                        ret += "..., "
                    ret += f"{str(self.value[-1])}"
                    return ret
                case "SWAP":
                    ret = f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}() # "
                    assert isinstance(self.mnemonic_num, int)
                    if self.mnemonic_num >= 2:
                        ret += f"{str(self.value[0])}, ..., {str(self.value[-1])}"
                    else:
                        ret += f"{str(self.value[0])}, {str(self.value[-1])}"
                    return ret
                case "LOG":
                    return f"{Colors.BOLD}{self.type}{self.mnemonic_num}{Colors.ENDC}({str(self.value)[1:-1]})"
                # case "CREATE":
                # case "CALL":
                # case "CALLCODE":
                # case "RETURN":
                # case "DELEGATECALL":
                # case "CREATE2":
                # case "STATICCALL":
                # case "REVERT":
                # case "INVALID":
                # case "SELFDESTRUCT":
                case _:
                    if self.input_count == 1:
                        return f"{Colors.BOLD}{self.type}{Colors.ENDC}({Node.unwrap(self.value[0])})"
                    else:
                        return f"{Colors.BOLD}{self.type}{Colors.ENDC}({str(self.value)[1:-1]})"
