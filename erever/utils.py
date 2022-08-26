
def bytes_to_long(x):
    return int.from_bytes(x, "big")


def long_to_bytes(x):
    return bytes.fromhex(hex(x)[2:])


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