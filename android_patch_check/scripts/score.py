import json
from pathlib import Path

result = dict()
for report in Path("oppo_reports").glob("*.json"):
    with report.open() as fp:
        data = json.load(fp)
    summary = data["Summary"]
    filemd5 = report.stem
    score = summary["Missing"] * 10 + summary["Claimed"]
    result[filemd5] = score


result = dict(sorted(result.items(), key=lambda item: item[1], reverse=True))

with open("oppo_sorted.json", "w") as fp:
    json.dump(result, fp, indent=2)