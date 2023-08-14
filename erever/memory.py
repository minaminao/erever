from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .types import Gas
from .utils import decode_printable_with_color


class Memory:
    memory: list[int]
    mstore_l_for_colorize: int | None
    mstore_r_for_colorize: int | None

    def __init__(self) -> None:
        self.memory = []

        self.mstore_l_for_colorize = None
        self.mstore_r_for_colorize = None

    def extend(self, size: int) -> Gas:
        if size % 0x20 > 0:
            size += 0x20 - size % 0x20
        if len(self.memory) >= size:
            return 0
        gas = self.calculate_gas_extend_memory(size)
        self.memory += [0] * (size - len(self.memory))
        return gas

    def get_as_bytes(self, offset: int, size: int) -> bytes:
        self.extend(offset + size)
        return bytes(self.memory[offset : offset + size])

    def get_as_hex(self, offset: int, size: int) -> str:
        return self.get_as_bytes(offset, size).hex()

    def store8(self, offset: int, value: int) -> None:
        assert value < 0x100
        self.extend(offset + 1)
        self.memory[offset] = value

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = offset + 1

    def store256(self, offset: int, value: int) -> Gas:
        value_bytes = value.to_bytes(32, "big")
        r = offset + 32
        allocation_gas = self.extend(r)
        for i, b in enumerate(value_bytes):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r
        return allocation_gas

    def store(self, offset: int, value: bytes) -> Gas:
        r = offset + len(value)
        allocation_gas = self.extend(r)
        for i, b in enumerate(value):
            self.memory[offset + i] = b
        for i, b in enumerate(value):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r
        return allocation_gas

    def load(self, offset: int) -> int:
        self.extend(offset + 32)
        return bytes_to_long(bytes(self.memory[offset : offset + 32]))

    def to_string(self, line_length: int = 0x20) -> list[str]:
        s = bytes(self.memory).hex()
        ret = []

        def zero_to_gray(s: str) -> str:
            ret = ""
            for i in range(0, len(s), 2):
                b = s[i : i + 2]
                if b == "00":
                    ret += Colors.GRAY + b + Colors.ENDC
                else:
                    ret += b
            return ret

        for i in range(0, len(s), 2 * line_length):
            ret.append(s[i : i + 2 * line_length])

        decoded_lines = []
        for i, line in enumerate(ret):
            decoded_line = decode_printable_with_color(
                line, i * line_length, self.mstore_l_for_colorize, self.mstore_r_for_colorize
            )
            decoded_lines.append(decoded_line)

        modified = (0, 0)
        if self.mstore_l_for_colorize is not None and self.mstore_r_for_colorize is not None:
            l_i = self.mstore_l_for_colorize // line_length
            l_j = 2 * (self.mstore_l_for_colorize % line_length)
            r_i = self.mstore_r_for_colorize // line_length
            r_j = 2 * (self.mstore_r_for_colorize % line_length)
            if r_j == 0:
                r_i -= 1
                r_j = 2 * line_length
            if l_i == r_i:
                ret[l_i] = (
                    zero_to_gray(ret[l_i][:l_j])
                    + Colors.GREEN
                    + ret[l_i][l_j:r_j]
                    + Colors.ENDC
                    + zero_to_gray(ret[l_i][r_j:])
                )
            else:
                ret[l_i] = zero_to_gray(ret[l_i][:l_j]) + Colors.GREEN + ret[l_i][l_j:] + Colors.ENDC
                for i in range(l_i + 1, r_i):
                    ret[i] = Colors.GREEN + ret[i] + Colors.ENDC
                ret[r_i] = Colors.GREEN + ret[r_i][:r_j] + Colors.ENDC + zero_to_gray(ret[r_i][r_j:])
            modified = (l_i, r_i + 1)
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None

        for i in range(0, len(ret)):
            if modified[0] <= i < modified[1]:
                ret[i] = ret[i] + " | " + decoded_lines[i]
            else:
                ret[i] = zero_to_gray(ret[i]) + " | " + decoded_lines[i]

        return ret

    def calculate_gas_extend_memory(self, size: int) -> Gas:
        return Memory.calculate_memory_gas_cost(size) - Memory.calculate_memory_gas_cost(len(self.memory))

    @staticmethod
    def calculate_memory_gas_cost(size: int) -> Gas:
        GAS_MEMORY = 3
        size_in_words = (size + 31) // 32
        linear_cost = size_in_words * GAS_MEMORY
        quadratic_cost = size_in_words**2 // 512
        total_gas_cost = linear_cost + quadratic_cost
        return total_gas_cost
