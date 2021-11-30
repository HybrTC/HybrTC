import json
import sys
from pathlib import Path
from numpy import log
import pandas as pd

DIR = Path(sys.argv[1])
FN = DIR / "perf_cuckoohashing.json"
assert FN.exists() and FN.is_file()


data = json.loads(FN.read_text())


def handle_record(record):
    timer = {t["name"]: t["clock"] for t in record["timer"]}

    return {
        "log_count": record["log_count"],
        "build": (timer["build:done"] - timer["build:start"]) / 1000000,
        "match": (timer["match:done"] - timer["match:start"]) / 1000000,
    }


df = pd.DataFrame([handle_record(rec) for rec in data])
df = df.groupby("log_count").describe()

df.to_excel(DIR / "perf_cuckoohashing.xlsx")
