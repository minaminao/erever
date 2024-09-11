from Crypto.Util.number import bytes_to_long

from .colors import Colors
from .types import Gas
from .utils import decode_printable_with_color, is_overlapping


class Memory:
    memory: list[int]
    mstore_l_for_colorize: int | None
    mstore_r_for_colorize: int | None
    MAX_MEMORY_INDEX = 1 << 24

    def __init__(self) -> None:
        self.memory = []

        self.mstore_l_for_colorize = None
        self.mstore_r_for_colorize = None

    def extend(self, size: int) -> Gas:
        if size > Memory.MAX_MEMORY_INDEX:
            raise Exception(f"Memory size too large: {size}")
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

    def to_string(self, line_length: int = 0x20, memory_range: list[tuple[int, int]] | None = None) -> list[str]:
        memory_length = len(self.memory)
        memory_hex = bytes(self.memory).hex()
        ret = []
        ret_lefts = []

        def zero_to_gray(s: str) -> str:
            ret = ""
            for i in range(0, len(s), 2):
                b = s[i : i + 2]
                if b == "00":
                    ret += Colors.GRAY + b + Colors.ENDC
                else:
                    ret += b
            return ret

        if memory_range is None:
            memory_range = [(0, memory_length)]
        addrs = []
        hr_indices = []
        adding = False
        for i in range(0, memory_length, line_length):
            addr_l = i
            addr_r = i + line_length
            if any(is_overlapping(addr_l, addr_r, left, right) for left, right in memory_range):
                ret.append(memory_hex[2 * i : 2 * (i + line_length)])
                ret_lefts.append(i)
                addrs.append(hex(addr_l))
                adding = True
            else:
                if adding:
                    hr_indices.append(len(ret))
                adding = False

        decoded_lines = []

        if (
            self.mstore_l_for_colorize is not None
            and self.mstore_r_for_colorize is not None
            and self.mstore_l_for_colorize != self.mstore_r_for_colorize
        ):
            _l_i = self.mstore_l_for_colorize // line_length
            l_j = 2 * (self.mstore_l_for_colorize % line_length)
            r_i = self.mstore_r_for_colorize // line_length
            r_j = 2 * (self.mstore_r_for_colorize % line_length)

            if r_j == 0:
                r_i -= 1
                r_j = 2 * line_length

            for ret_i in range(0, len(ret)):
                line_left = ret_lefts[ret_i]
                line_right = line_left + line_length

                if not is_overlapping(
                    line_left,
                    line_right,
                    self.mstore_l_for_colorize,
                    self.mstore_r_for_colorize,
                ):
                    decoded_lines.append(decode_printable_with_color(ret[ret_i]))
                    ret[ret_i] = zero_to_gray(ret[ret_i])
                    continue

                if self.mstore_l_for_colorize <= line_left and line_right <= self.mstore_r_for_colorize:
                    decoded_lines.append(decode_printable_with_color(ret[ret_i], 0, line_length))
                    ret[ret_i] = Colors.GREEN + ret[ret_i] + Colors.ENDC
                elif line_left < self.mstore_l_for_colorize and self.mstore_r_for_colorize < line_right:
                    decoded_lines.append(decode_printable_with_color(ret[ret_i], l_j // 2, r_j // 2))
                    ret[ret_i] = (
                        zero_to_gray(ret[ret_i][:l_j])
                        + Colors.GREEN
                        + ret[ret_i][l_j:r_j]
                        + Colors.ENDC
                        + zero_to_gray(ret[ret_i][r_j:])
                    )

                elif line_left < self.mstore_l_for_colorize and line_right <= self.mstore_r_for_colorize:
                    decoded_lines.append(decode_printable_with_color(ret[ret_i], l_j // 2, line_length))
                    ret[ret_i] = zero_to_gray(ret[ret_i][:l_j]) + Colors.GREEN + ret[ret_i][l_j:] + Colors.ENDC
                elif self.mstore_l_for_colorize <= line_left and self.mstore_r_for_colorize < line_right:
                    decoded_lines.append(decode_printable_with_color(ret[ret_i], 0, r_j // 2))
                    ret[ret_i] = Colors.GREEN + ret[ret_i][:r_j] + Colors.ENDC + zero_to_gray(ret[ret_i][r_j:])
                else:
                    assert (
                        False
                    ), f"Unreachable {line_left} {line_right} {self.mstore_l_for_colorize} {self.mstore_r_for_colorize}"
            self.mstore_l_for_colorize = None
            self.mstore_r_for_colorize = None
        else:
            for i in range(0, len(ret)):
                decoded_lines.append(decode_printable_with_color(ret[i]))
                ret[i] = zero_to_gray(ret[i])

        # TODO: cleanup
        new_ret = []
        show_decode = True
        assert len(ret) == len(decoded_lines), f"{len(ret)} != {len(decoded_lines)}"
        for i in range(0, len(ret)):
            if i in hr_indices:
                new_ret.append("-" * 10)
            if show_decode:
                new_ret.append(ret[i] + " | " + decoded_lines[i] + " | " + addrs[i])
            else:
                new_ret.append(ret[i] + " | " + addrs[i])
        ret = new_ret

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
