from Crypto.Util.number import bytes_to_long


class EOFHeader:
    def __init__(
        self,
        version: int,
        types_size: int,
        num_code_sections: int,
        code_sizes: list[int],
        num_container_sections: int | None,
        container_sizes: list[int],
        data_size: int,
    ) -> None:
        self.version = version
        self.types_size = types_size
        self.num_code_sections = num_code_sections
        self.code_sizes = code_sizes
        self.num_container_sections = num_container_sections
        self.container_sizes = container_sizes
        self.data_size = data_size


def parse_eof_header(bytecode: bytes) -> tuple[EOFHeader, int]:
    p = 0

    print("Header:")

    magic = bytecode[p : p + 2]
    assert magic == b"\xef\x00", "Invalid magic"
    print(f"  Magic: {magic.hex()}")
    p += 2

    version = bytes_to_long(bytecode[p : p + 1])
    assert version == 1, "Invalid version"
    print(f"  Version: {version}")
    p += 1

    kind_types = bytecode[p : p + 1]
    assert kind_types == b"\x01", "Invalid kind_types"
    print(f"  Kind types: {kind_types.hex()}")
    p += 1

    types_size = bytes_to_long(bytecode[p : p + 2])
    assert 0x0004 <= types_size <= 0x1000, f"types_size {types_size:#x} is out of valid range (0x0004 - 0x1000)"
    assert types_size % 4 == 0, f"types_size {types_size:#x} is not a multiple of 4"
    print(f"  Types size: {types_size}")
    p += 2

    kind_code = bytecode[p : p + 1]
    assert kind_code == b"\x02", "Invalid kind_code"
    print(f"  Kind code: {kind_code.hex()}")
    p += 1

    num_code_sections = bytes_to_long(bytecode[p : p + 2])
    assert (
        0x0001 <= num_code_sections <= 0x0400
    ), f"num_code_sections {num_code_sections:#x} is out of valid range (0x0001 - 0x0400)"
    assert (
        types_size // 4 == num_code_sections
    ), f"Mismatch: types_size // 4 ({types_size // 4}) does not equal num_code_sections ({num_code_sections})"
    print(f"  Num code sections: {num_code_sections}")
    p += 2

    code_sizes = []
    for _ in range(num_code_sections):
        code_size = bytes_to_long(bytecode[p : p + 2])
        assert 0x0001 <= code_size <= 0xFFFF, "Invalid code_size"
        print(f"  Code size: {code_size}")
        p += 2
        code_sizes.append(code_size)

    kind_container = bytecode[p : p + 1]
    container_sizes = []
    num_container_sections = None
    if kind_container == b"\x03":
        print(f"  Kind container: {kind_container.hex()}")
        p += 1

        num_container_sections = bytes_to_long(bytecode[p : p + 2])
        assert 0x0001 <= num_container_sections <= 0x0100, "Invalid num_container_sections"
        print(f"  Num container sections: {num_container_sections}")
        p += 2

        for _ in range(num_container_sections):
            container_size = bytes_to_long(bytecode[p : p + 2])
            assert 0x0001 <= container_size <= 0xFFFF, "Invalid container_size"
            print(f"  Container size: {container_size}")
            p += 2
            container_sizes.append(container_size)

    kind_data = bytecode[p : p + 1]
    assert kind_data == b"\x04", "Invalid kind_data"
    print(f"  Kind data: {kind_data.hex()}")
    p += 1

    data_size = bytes_to_long(bytecode[p : p + 2])
    assert 0x0000 <= data_size <= 0xFFFF, "Invalid data_size"
    print(f"  Data size: {data_size}")
    p += 2

    terminator = bytecode[p : p + 1]
    assert terminator == b"\x00", "Invalid terminator"
    print(f"  Terminator: {terminator.hex()}")
    p += 1

    header = EOFHeader(
        version=version,
        types_size=types_size,
        num_code_sections=num_code_sections,
        code_sizes=code_sizes,
        num_container_sections=num_container_sections,
        container_sizes=container_sizes,
        data_size=data_size,
    )

    print()
    return header, p


class EOFCode:
    def __init__(
        self,
        inputs: int,
        outputs: int,
        max_stack_height: int,
        code: bytes,
    ) -> None:
        self.inputs = inputs
        self.outputs = outputs
        self.max_stack_height = max_stack_height
        self.code = code


class EOFContainer:
    def __init__(
        self,
        container: bytes,
    ) -> None:
        self.container = container


class EOFData:
    def __init__(
        self,
        data: bytes,
    ) -> None:
        self.data = data


class EOF:
    def __init__(
        self,
        header: EOFHeader,
        codes: list[EOFCode],
        containers: list[EOFContainer],
        data: EOFData,
        return_stack: list[tuple[int, int]] | None = None,
    ) -> None:
        self.header = header
        self.codes = codes
        self.containers = containers
        self.data = data
        self.return_stack = return_stack if return_stack is not None else []


def parse_eof_body(bytecode: bytes, header: EOFHeader, p: int) -> tuple[EOF, int]:
    print("Body:")

    types = []

    for _ in range(header.types_size // 4):
        inputs = bytes_to_long(bytecode[p : p + 1])
        assert 0x00 <= inputs <= 0x7F, "Invalid inputs"
        print(f"  Inputs: {inputs}")
        p += 1
        outputs = bytes_to_long(bytecode[p : p + 1])
        assert 0x00 <= outputs <= 0x80, "Invalid outputs"
        print(f"  Outputs: {outputs}")
        p += 1
        max_stack_height = bytes_to_long(bytecode[p : p + 2])
        assert 0x0000 <= max_stack_height <= 0x03FF, "Invalid max_stack_height"
        print(f"  Max stack height: {max_stack_height}")
        p += 2
        types.append((inputs, outputs, max_stack_height))

    code = []
    for i, code_size in enumerate(header.code_sizes):
        inputs, outputs, max_stack_height = types[i]
        code_bytes = bytecode[p : p + code_size]
        print(f"  Code: {code_bytes.hex()}")
        p += code_size
        code.append(EOFCode(inputs, outputs, max_stack_height, code_bytes))

    containers = []
    if header.num_container_sections is not None:
        for container_size in header.container_sizes:
            container = bytecode[p : p + container_size]
            print(f"  Container: {container.hex()}")
            p += container_size
            containers.append(EOFContainer(container))

    data = bytecode[p : p + header.data_size]

    eof = EOF(header, code, containers, EOFData(data))
    print()
    return eof, p
