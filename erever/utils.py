import string

from eth_typing import ChecksumAddress
from web3 import Web3

from .colors import Colors

UINT256_MAX = (1 << 256) - 1
SIGN_MASK = 1 << 255

PRINTABLE = string.printable[:-5]
TAB_SIZE = 4


def uint256(x: int) -> int:
    return x & UINT256_MAX


def int256(x: int) -> int:
    x &= UINT256_MAX
    if x & SIGN_MASK:
        return -((1 << 256) - x)
    else:
        return x


def pad(hex_number: str, n: int) -> str:
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    hex_number = "0x" + "0" * (n - len(hex_number)) + hex_number
    return hex_number


def pad_even(hex_number: str) -> str:
    if hex_number[:2] == "0x":
        hex_number = hex_number[2:]
    n = len(hex_number) + len(hex_number) % 2
    return pad(hex_number, n)


def decode_printable_with_color(
    hex_string: str,
    i_start: int | None = None,
    mstore_l_for_colorize: int | None = None,
    mstore_r_for_colorize: int | None = None,
) -> str:
    if hex_string[:2] == "0x":
        hex_string = hex_string[2:]

    decoded = ""
    for i in range(0, len(hex_string), 2):
        c = chr(int(hex_string[i : i + 2], 16))
        if c not in PRINTABLE:
            c = "."
        if (
            mstore_l_for_colorize is not None
            and mstore_r_for_colorize is not None
            and i_start is not None
            and mstore_l_for_colorize <= i_start + i // 2 < mstore_r_for_colorize
        ):
            c = Colors.GREEN + c + Colors.ENDC
        elif c not in PRINTABLE:
            c = Colors.GRAY + "." + Colors.ENDC
        decoded += c
    return decoded


def is_invocation_mnemonic(mnemonic: str) -> bool:
    return mnemonic in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2", "SELFDESTRUCT", "LOG"]


def int_to_check_sum_address(x: int) -> ChecksumAddress:
    return Web3.to_checksum_address(pad(hex(x), 40))
