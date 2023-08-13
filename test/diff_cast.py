import sys
import re
import json
from pathlib import Path

"""
Usage:
$ erever trace --rpc-url $RPC_MAINNET --tx <tx hash> --output-json > ~/tmp/erever.json
$ cast run <tx hash> --trace-printer -q > ~/tmp/cast.txt
$ python test/diff_cast.py ~/tmp/erever.json ~/tmp/cast.txt
"""

if len(sys.argv) != 3:
    print("Usage: python diff_cast.py <erever output> <cast output>")
    exit()

erever_output_file = Path(sys.argv[1])
cast_output_file = Path(sys.argv[2])

erever_output = json.load(erever_output_file.open())
trace_logs = erever_output["trace_logs"]
# {'mnemonic_raw': 'SWAP2', 'mnemonic': 'SWAP', 'input': [408, 308, 308], 'stack_after_execution': [3055364086, 249, 1097077688018008265106216665536940668749033598146, 10000000000000000000000, 132, 96, 308, 308, 408]}

# cast_output_file is a big file, so we don't want to read it all into memory
with cast_output_file.open() as f:
    # Example: depth:1, PC:0, gas:0x1ba2740(28976960), OPCODE: "PUSH1"(96)  refund:0x0(0) Stack:[], Data size:0, Data: 0x
    pattern = re.compile(
        r"depth:(\d+), PC:(\d+), gas:(0x[0-9a-f]+)\((\d+)\), OPCODE: \"([A-Z0-9]+)\"\((\d+)\)  refund:(0x[0-9a-f]+)\((\d+)\) Stack:\[(.*)\], Data size:(\d+), Data: (0x[0-9a-f]*)"
    )
    trace_log_i = 0
    for line in f:
        line = line.strip()
        if line.startswith("SM CALL:"):
            print(line)
            continue
        result = pattern.match(line)
        assert result is not None
        depth = int(result.group(1))
        pc = int(result.group(2))
        gas = int(result.group(4))
        mnemonic_raw = result.group(5).replace("SHA3", "KECCAK256")
        refund = int(result.group(8))
        stack = [int(x.replace("_U256", ""), 16) for x in (result.group(9).split(",") if result.group(9) != "" else [])]
        data_size = int(result.group(10))
        data = result.group(11)
        trace_log = trace_logs[trace_log_i]

        erever_stack = trace_log["stack_after_execution"]
        erever_prev_stack = trace_logs[trace_log_i - 1]["stack_after_execution"] if trace_log_i > 0 else []

        invalid = False
        invalid |= mnemonic_raw != trace_log["mnemonic_raw"]
        invalid |= stack != erever_prev_stack

        print("erever", trace_log["mnemonic_raw"], erever_prev_stack)
        print("cast  ", mnemonic_raw, stack)

        if invalid:
            print()
            print("INVALID")
            break

        trace_log_i += 1
