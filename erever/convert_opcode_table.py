import re

with open("erever/opcode_table_in_yellowpaper.tex") as f:
    for line in f.readlines():

        #oops
        line = re.sub(r'\\linkdest\{.+\}\{\}', '', line)
        
        if line[:2] != "0x":
            continue
        line = line.strip()
        assert line[-2:] == R"\\"
        line = line[:-2]
        items = line.split(" & ")
        assert len(items) == 5
        items[0] = items[0].strip()
        items[1] = items[1].replace("{\\small ", "").replace("}", "")
        items[2] = int(items[2].strip().replace("$\\varnothing$", "0"))
        items[3] = int(items[3].strip().replace("$\\varnothing$", "0"))
        items[4] = items[4].strip().replace("\\hyperlink{chain_id}{chain ID}", "chain ID").replace("\\textit{prior}", "prior")

        # oops
        if items[0] == "0x34":
            items[4] += " this execution."
        elif items[0] == "0x36":
            items[4] += " environment."
        elif items[0] == "0x3d":
            items[4] += " environment."
        elif items[0] == "0x58":
            items[4] += " corresponding to this instruction."
        elif items[0] == "0x5a":
            items[4] += " for the cost of this instruction."
        elif items[0] == "0xf4":
            items[4] += " persisting the current values for sender and value."
        assert items[4][-1] == "."

        # oops
        if items[1] == "PUSH2":
            for i in range(1, 31):
                value = hex(0x60 + i)
                print(f'{value}: ("PUSH{i+1}", 0, 1, "Place {i+1} byte item on stack."),')
            continue
        if items[1] == "DUP2":
            for i in range(1, 15):
                value = hex(0x80 + i)
                if i == 1:
                    print(f'{value}: ("DUP{i+1}", {i+1}, {i+2}, "Duplicate 2nd stack item."),')
                elif i == 2:
                    print(f'{value}: ("DUP{i+1}", {i+1}, {i+2}, "Duplicate 3rd stack item."),')
                else:
                    print(f'{value}: ("DUP{i+1}", {i+1}, {i+2}, "Duplicate {i+1}th stack item."),')
            continue
        if items[1] == "SWAP2":
            for i in range(1, 15):
                value = hex(0x90 + i)
                if i == 1:
                    print(f'{value}: ("SWAP{i+1}", {i+2}, {i+2}, "Exchange 1st and 3rd stack items."),')
                else:
                    print(f'{value}: ("SWAP{i+1}", {i+2}, {i+2}, "Exchange 1st and {i+2}th stack items."),')
            continue
        if items[1] == "LOG1":
            print(f'0xa1: ("LOG1", 3, 0, "Append log record with one topic."),')
            print(f'0xa2: ("LOG2", 4, 0, "Append log record with two topics."),')
            print(f'0xa3: ("LOG3", 5, 0, "Append log record with three topics."),')
            continue

        print(f'{items[0]}: ("{items[1]}", {items[2]}, {items[3]}, "{items[4]}"),')


