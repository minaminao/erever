from enum import Enum

from .context import Context
from .disassemble import disassemble
from .opcodes import OPCODES
from .utils import UINT256_MAX, pad


class ControlType(Enum):
    BEFORE_JUMPDEST = 0
    JUMP = 1
    JUMPI = 2
    END = 3
    BAD = -1


def disassemble_mermaid(context: Context, entrypoint: int = 0x00, max_steps: int = UINT256_MAX) -> None:
    """
    ブロックの開始
    - 0x00
    - JUMPDEST
    - JUMPIの一つ後
    ブロックの終了
    - JUMP
    - JUMPDESTの一つ前
    - REVERT
    - INVALID
    - SELFDESTRUCT
    - STOP
    - RETURN
    """

    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    start_addresses = [0x00]

    for i in range(len(context.bytecode)):
        value = context.bytecode[i]
        if value not in OPCODES:
            continue
        mnemonic = OPCODES[value][0]
        if mnemonic == "JUMPDEST":
            # JUMPIの一つ後で追加済みならば追加しない
            if start_addresses[-1] != i:
                start_addresses.append(i)
        elif mnemonic == "JUMPI":
            start_addresses.append(i + 1)

    def disassemble_block(start_address: int) -> tuple[bool, int, ControlType, list[str]]:
        """
        return is_valid_block, end_address, control_type, instructions
        """

        pc = start_address
        instructions = []
        while pc < len(context.bytecode):
            next_pc = pc + 1
            value = context.bytecode[pc]

            if value in OPCODES:
                mnemonic, stack_input_count, _stack_output_count, _description, stack_input_names = OPCODES[value]
            else:
                instructions.append(f"{pad(hex(pc), LOCATION_PAD_N)}: 0x (?)")
                return False, pc, ControlType.BAD, instructions

            if mnemonic.startswith("PUSH"):
                mnemonic_num = int(mnemonic[4:])
                next_pc = pc + 1 + mnemonic_num
            elif mnemonic.startswith("DUP"):
                mnemonic_num = int(mnemonic[3:])
            elif mnemonic.startswith("SWAP"):
                mnemonic_num = int(mnemonic[4:])
            elif mnemonic.startswith("LOG"):
                mnemonic_num = int(mnemonic[3:])

            if mnemonic.startswith("PUSH"):
                instructions.append(
                    f"{pad(hex(pc), LOCATION_PAD_N)}: {mnemonic}  0x{context.bytecode[pc+1:pc+1+mnemonic_num].hex()}"
                )
            else:
                instructions.append(f"{pad(hex(pc), LOCATION_PAD_N)}: {mnemonic}")

            if pc != start_address and mnemonic == "JUMPDEST":
                return True, pc - 1, ControlType.BEFORE_JUMPDEST, instructions
            elif mnemonic == "JUMP":
                return True, pc, ControlType.JUMP, instructions
            elif mnemonic == "JUMPI":
                return True, pc, ControlType.JUMPI, instructions
            elif mnemonic in ["REVERT", "INVALID", "SELFDESTRUCT", "STOP", "RETURN"]:
                return True, pc, ControlType.END, instructions

            pc = next_pc

        assert False

    graph = ""
    for start_address in start_addresses:
        is_valid_block, end_address, control_type, instructions = disassemble_block(start_address)
        if not is_valid_block:
            continue
        block = "\\n".join(instructions)
        max_steps = len(instructions)
        error = False
        try:
            last_jump_to_address = disassemble(
                context=context,
                trace=True,
                entrypoint=start_address,
                max_steps=max_steps,
                decode_stack=False,
                ignore_stack_underflow=True,
                silent=True,
            ).last_jump_to_address
        except Exception:
            error = True

        block_id = pad(hex(start_address), LOCATION_PAD_N) if start_address != entrypoint else "START"
        if error:
            graph += f"{block_id}({block}) --> ERROR\n"
            continue
        match control_type:
            case ControlType.BEFORE_JUMPDEST:
                next_block_id = pad(hex(end_address), LOCATION_PAD_N)
                graph += f"{block_id}({block}) --> {next_block_id}\n"
            case ControlType.JUMP:
                assert type(last_jump_to_address) is int
                next_block_id = pad(hex(last_jump_to_address), LOCATION_PAD_N)
                graph += f"{block_id}({block}) --jump--> {next_block_id}\n"
            case ControlType.JUMPI:
                assert type(last_jump_to_address) is int
                next_block_id = pad(hex(last_jump_to_address), LOCATION_PAD_N)
                graph += f"{block_id}({block}) --jump--> {next_block_id}\n"
                next_block_id = pad(hex(end_address + 1), LOCATION_PAD_N)
                graph += f"{block_id} --> {next_block_id}\n"
            case ControlType.END:
                next_block_id = "END"
                graph += f"{block_id}({block}) --> {next_block_id}\n"

    print(
        """<html lang="en">
    <head>
        <meta charset="utf-8" />
    </head>
    <body>"""
        + f"""<pre class="mermaid">

flowchart TB 
{graph}
    </pre>"""
        + """<script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({ startOnLoad: true });
    </script>
    <style>
    .mermaid .node .label {
        text-align: left !important;
    }
    </style>
    </body>
    </html>
    """
    )
