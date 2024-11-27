import os
import json
from pathlib import Path

with open("/home/dell/tmp_lyz/romUrl.txt") as fp:
    repoUrls = fp.readlines()

result = dict()
for repoUrl in repoUrls[:390] + repoUrls[549:600] + repoUrls[1069:1089]:
    local_repo = (
        Path("/data/android_rom/dumps")
        / repoUrl.strip()[len("https://git.rip/dumps/") :]
    )
    if not local_repo.exists():
        continue
    print(local_repo)
    os.chdir(str(local_repo))
    outputs = os.popen("git branch -a").read()
    outputs = outputs.splitlines()
    branches = set()
    for line in outputs:
        if "remotes/origin/HEAD ->" in line:
            continue
        if line.startswith("*"):
            continue
        line = line.strip()
        print("\t", line)
        branches.add(line)

    if branches:
        result[str(local_repo)] = list(branches)

with open("/home/dell/tmp_ls/PatchSher/scripts/repobranches.json", "w") as fp:
    json.dump(result, fp, indent=2, sort_keys=True)
