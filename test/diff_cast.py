import sys
from pathlib import Path

"""
Usage:
$ erever trace <tx hash> > ~/tmp/a.txt
$ cast run <tx hash> --trace-printer -q > ~/tmp/b.txt
$ python diff_cast.py ~/tmp/a.txt ~/tmp/b.txt
"""

if len(sys.argv) != 3:
    print("Usage: python diff_cast.py <erever output> <cast output>")
    exit()

cast_output_file = Path(sys.argv[1])
erever_output_file = Path(sys.argv[2])

cast_output = cast_output_file.open().readlines()
erever_output = erever_output_file.open().readlines()

for line in cast_output:
    print(line)
    break

