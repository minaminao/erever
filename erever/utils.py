from Crypto.Util.number import bytes_to_long, long_to_bytes

UINT256_MAX = (1 << 256) - 1
SIGN_MASK = 1 << 255


def uint256(x: int):
    return x & UINT256_MAX


def int256(x: int):
    x &= UINT256_MAX
    if x & SIGN_MASK:
        return -((1 << 256) - x)
    else:
        return x


def pad(hex_number: str, n: int):
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    hex_number = "0x" + "0" * (n - len(hex_number)) + hex_number
    return hex_number


def pad_even(hex_number: str):
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    n = len(hex_number) + len(hex_number) % 2
    return pad(hex_number, n)
