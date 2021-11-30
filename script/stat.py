import json
import re
import sys
from itertools import groupby
from pathlib import Path

import pandas as pd

DIR = Path(sys.argv[1])
assert DIR.exists() and DIR.is_dir()
CLIENT_REG = re.compile("c/(s\d): (.*)")


def process_test_session(policy, points):
    points = {
        k: [v["clock"] for v in it]
        for k, it in groupby(
            sorted(points, key=lambda p: p["name"]), key=lambda p: p["name"]
        )
    }

    if policy == "SELECT_ONLY":
        return max(points["result received"]) - min(points["set_client_query:start"])
    else:
        t1 = max(points["set_client_query:done"]) - min(
            points["set_client_query:start"]
        )

        t2 = max(points["result received"]) - min(
            points["gen_compute_request:start"] + points["pro_compute_request:start"]
        )
        return t1 + t2


def process_test(fn):
    data = json.loads(Path(fn).read_text())

    test_id = data["test_id"]
    policy = data["meta"]["PSI_AGGREGATE_POLICY"]

    points = {f"s{i}": [] for i in range(data["meta"]["PSI_SERVER_NUMBER"])}

    for reporter, records in groupby(
        sorted(data["time"], key=lambda obj: obj["reporter"]),
        key=lambda obj: obj["reporter"],
    ):
        if reporter == "c":
            for rec in records:
                mobj = CLIENT_REG.match(rec["name"])
                if mobj:
                    groups = mobj.groups()
                    points[groups[0]].append({"name": groups[1], "clock": rec["clock"]})

        else:
            for rec in records:
                points[rec["reporter"]].append(
                    {"name": rec["name"], "clock": rec["clock"]}
                )

    duration = min(process_test_session(policy, v) for v in points.values())

    return {
        "test_id": test_id,
        "duration": duration,
        **data["meta"],
    }


if __name__ == "__main__":
    data = [process_test(fn) for fn in sorted(DIR.glob("2021*.json"))]
    df = pd.DataFrame(data)
    df["duration"] = df["duration"] / 1000000
    df = df.groupby(
        [
            "PSI_SELECT_POLICY",
            "PSI_AGGREGATE_POLICY",
            "PSI_SERVER_NUMBER",
            "PSI_DATA_SET_SIZE_LOG",
        ]
    )["duration"].describe()
    df.to_excel(DIR / "20211128.xlsx")
