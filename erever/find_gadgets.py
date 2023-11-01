from .colors import Colors
from .context import Context
from .disassemble import disassemble
from .disassemble_symbolic import disassemble_symbolic
from .utils import pad


def find_gadgets(
    context: Context,
    max_steps: int = 1000,
) -> None:
    disassembled_code = disassemble(context, silent=True).disassemble_code
    LOCATION_PAD_N = len(hex(len(context.bytecode))[2:])

    for pc, mnemonic, _push_v in disassembled_code:
        if mnemonic != "JUMPDEST":
            continue

        print(f"Checking {pad(hex(pc), LOCATION_PAD_N)}")
        gadget_list = disassemble_symbolic(
            context, entrypoint=pc, show_symbolic_stack=True, max_steps=max_steps, silent=True, return_gadget_list=True
        )
        assert gadget_list is not None
        for gadget in gadget_list:
            jump_pc, jump_dst, var_n, stack, data_changes, conditions = gadget
            print(" ", "Gadget:")
            print(" ", " ", "    entry pc:", pad(hex(pc), LOCATION_PAD_N))
            print(" ", " ", "     jump pc:", pad(hex(jump_pc), LOCATION_PAD_N))
            print(" ", " ", "    jump dst:", jump_dst)
            print(" ", " ", " stack input:", var_n)
            print(" ", " ", "stack output:", len(stack), stack)
            if len(data_changes) > 0:
                print(" ", " ", "data changes:")
                for data_change in data_changes:
                    print(" " * 10, data_change)
            if len(conditions) > 0:
                print(" ", " ", "  conditions:")
                for condition, condition_pc, is_met in conditions:
                    if is_met:
                        print(
                            " " * 10
                            + f"{Colors.GREEN} {pad(hex(condition_pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.GREEN}== true{Colors.ENDC}"
                        )
                    else:
                        print(
                            " " * 10
                            + f"{Colors.RED} {pad(hex(condition_pc), LOCATION_PAD_N)}{Colors.ENDC}: {condition} {Colors.RED}== false{Colors.ENDC}"
                        )
            print()
