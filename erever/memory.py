from Crypto.Util.number import bytes_to_long

from .utils import decode_printable_with_color


class Memory:
    def __init__(self):
        self.memory = []

        self.mstore_l_for_colorize = None
        self.mstore_r_for_colorize = None

    def __extend(self, size: int):
        if size % 0x20 > 0:
            size += (0x20 - size % 0x20)
        if len(self.memory) >= size:
            return
        self.memory += [0] * (size - len(self.memory))

    def get_hex(self, start: int, end: int) -> str:
        return bytes(self.memory[start:end]).hex()

    def store8(self, offset: int, value: int):
        assert value < 0x100
        self.__extend(offset + 1)
        self.memory[offset] = value

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = offset + 1

    def store256(self, offset: int, value: int):
        value = value.to_bytes(32, "big")
        r = offset + 32
        self.__extend(r)
        for i, b in enumerate(value):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r

    def store(self, offset: int, value: bytes):
        r = offset + len(value)
        self.__extend(r)
        for i, b in enumerate(value):
            self.memory[offset + i] = b
        for i, b in enumerate(value):
            self.memory[offset + i] = b

        self.mstore_l_for_colorize = offset
        self.mstore_r_for_colorize = r

    def load(self, offset: int):
        return bytes_to_long(bytes(self.memory[offset:offset+32]))

    def to_string(self, line_length=0x20) -> list[str]:
        s = bytes(self.memory).hex()
        ret = []

        def zero_to_gray(s):
            ret = ""
            for i in range(0, len(s), 2):
                b = s[i:i+2]
                if b == "00":
                    ret += Colors.GRAY + b + Colors.ENDC
                else:
                    ret += b
            return ret

        for i in range(0, len(s), 2 * line_length):
            ret.append(s[i:i + 2 * line_length])

        decoded_lines = []
        for i, line in enumerate(ret):
            decoded_line = decode_printable_with_color(line, i * line_length, self.mstore_l_for_colorize, self.mstore_r_for_colorize)
            decoded_lines.append(decoded_line)

        modified = (0, 0)
        if self.mstore_l_for_colorize is not None:
            l_i = self.mstore_l_for_colorize // line_length
            l_j = 2 * (self.mstore_l_for_colorize % line_length)
            r_i = self.mstore_r_for_colorize // line_length
            r_j = 2 * (self.mstore_r_for_colorize % line_length)
            if r_j == 0:
                r_i -= 1
                r_j = 2 * line_length
            if l_i == r_i:
                ret[l_i] = zero_to_gray(ret[l_i][:l_j]) + Colors.GREEN + ret[l_i][l_j:r_j] + Colors.ENDC + zero_to_gray(ret[l_i][r_j:])
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

