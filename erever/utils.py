import string

from Crypto.Util.number import bytes_to_long, long_to_bytes

from .colors import *

UINT256_MAX = (1 << 256) - 1
SIGN_MASK = 1 << 255

PRINTABLE = string.printable[:-5]
TAB_SIZE = 4


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


def decode_printable_with_color(hex_string: str) -> str:
    if hex_string[:2] == "0x":
        hex_string = hex_string[2:]
    decoded = ""
    for i in range(0, len(hex_string), 2):
        c = chr(int(hex_string[i:i + 2], 16))
        if c in PRINTABLE:
            decoded += c
        else:
            decoded += colors.GRAY + "." + colors.ENDC
    return decoded
