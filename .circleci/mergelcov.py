from pathlib import Path
from sys import argv
from subprocess import check_output

d = Path(argv[1])

cmd = ["lcov"]
for p in d.iterdir():
    cmd.extend(["--add-tracefile", str(p)])
cmd.extend(["--output", argv[2]])

print(check_output(cmd))
