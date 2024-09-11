import string

import rlp
from eth_typing import ChecksumAddress
from web3 import Web3

from .colors import Colors
from .types import AddressInt

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
    l_for_colorize: int | None = None,
    r_for_colorize: int | None = None,
) -> str:
    if hex_string[:2] == "0x":
        hex_string = hex_string[2:]

    decoded = ""
    for i in range(0, len(hex_string), 2):
        c = chr(int(hex_string[i : i + 2], 16))
        printable = c in PRINTABLE
        if not printable:
            c = "."
        if l_for_colorize is not None and r_for_colorize is not None and l_for_colorize <= i // 2 < r_for_colorize:
            c = Colors.GREEN + c + Colors.ENDC
        elif not printable:
            c = Colors.GRAY + "." + Colors.ENDC
        decoded += c
    return decoded


def is_invocation_mnemonic(mnemonic: str) -> bool:
    return mnemonic in [
        "CALL",
        "CALLCODE",
        "DELEGATECALL",
        "STATICCALL",
        "CREATE",
        "CREATE2",
        "SELFDESTRUCT",
        "LOG",
    ]


def int_to_check_sum_address(x: int) -> ChecksumAddress:
    return Web3.to_checksum_address(pad(hex(x), 40))


def is_overlapping(l1: int, r1: int, l2: int, r2: int) -> bool:
    return max(l1, l2) < min(r1, r2)


def compute_contract_address(address: AddressInt, nonce: int) -> AddressInt:
    return int.from_bytes(Web3.keccak(rlp.encode([address.to_bytes(20, "big"), nonce]))[-20:], "big")
