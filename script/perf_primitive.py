import json
import sys
from pathlib import Path
from numpy import log
import pandas as pd

DIR = Path(sys.argv[1])
FN = DIR / "perf_primitive.json"
assert FN.exists() and FN.is_file()


data = json.loads(FN.read_text())


def handle_record(record):
    timer = {t["name"]: t["clock"] for t in record}
    return (
        (timer["prp:done"] - timer["prp:start"]),
        (timer["enc:done"] - timer["enc:start"]),
    )


vals = list(zip(*[handle_record(rec) for rec in data]))

df = pd.DataFrame({"prp": list(vals[0]), "enc": list(vals[1])})
df = df.describe()

df.to_excel(DIR / "perf_primitive.xlsx")
