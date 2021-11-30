import json
from functools import reduce
from glob import glob
from itertools import chain, groupby
from pathlib import Path
from uuid import uuid1

import pandas as pd


def load_json(fn):
    return json.loads(Path(fn).read_bytes())


def pprint(obj):
    return json.dumps(obj, indent=True)


ATTRIBUTES = ["PSI_SELECT_POLICY", "PSI_AGGREGATE_POLICY", "SIZE"]

FEATURES_COMM = [
    "c:c/s0:sent",
    "c:c/s0:recv",
    "c:c/s1:sent",
    "c:c/s1:recv",
    "s0:c/p:sent",
    "s0:c/p:recv",
    "s0:s/p:sent",
    "s0:s/p:recv",
    "s0:s/c:sent",
    "s0:s/c:recv",
    "s1:c/p:sent",
    "s1:c/p:recv",
    "s1:s/p:sent",
    "s1:s/p:recv",
    "s1:s/c:sent",
    "s1:s/c:recv",
]

FEATURES_TIME = [
    "c:duration",
    "c:s0:attest",
    "c:s0:query",
    "c:s1:attest",
    "c:s1:query",
    "s0:c:set_client_query",
    "s0:a:build_bloom_filter",
    "s1:p:match_bloom_filter",
    "s0:a:aggregate",
    "s0:c:get_result",
    "s1:c:set_client_query",
    "s1:a:build_bloom_filter",
    "s0:p:match_bloom_filter",
    "s1:a:aggregate",
    "s1:c:get_result",
]


def drop_outliner(data, groupby, features, threshold):
    def outliner(column):
        std = column.std()
        avg = column.mean()
        lhs = avg - threshold * std
        rhs = avg + threshold * std
        return (column >= lhs) & (column <= rhs)

    valid_records = set()

    for group in data[groupby].drop_duplicates().values:
        bucket = data[
            reduce(
                pd.Series.__and__,
                map(lambda name, value: data[name] == value, groupby, group),
            )
        ]

        records = bucket[
            reduce(
                pd.Series.__and__,
                map(
                    lambda col: outliner(bucket[col]),
                    features,
                ),
            )
        ]

        valid_records.update(records.index)

    return data.loc[list(valid_records)]


SEL = {
    0x00: "PASSTHROUGH",
    0x10: "OBLIVIOUS_ALL",
    0x11: "OBLIVIOUS_ODD",
}

AGG = {
    0x00: "SELECT_ONLY",
    0x10: "JOIN_COUNT",
    0x11: "JOIN_SUM",
}


def process_client(fn):
    data = load_json(fn)

    meta = {
        "PSI_SERVER_NUMBER": data.get("PSI_SERVER_NUMBER"),
        "PSI_PAILLIER_PK_LEN": data.get("PSI_PAILLIER_PK_LEN"),
        "PSI_MELBOURNE_P": data.get("PSI_MELBOURNE_P"),
        "PSI_SELECT_POLICY": SEL[data.get("PSI_SELECT_POLICY")],
        "PSI_AGGREGATE_POLICY": AGG[data.get("PSI_AGGREGATE_POLICY")],
    }

    comm = [
        {
            "reporter": "c",
            "session": key,
            "sent": val["sent"],
            "recv": val["recv"],
        }
        for key, val in data.get("comm").items()
    ]

    time = [{"reporter": "c", **t} for t in data.get("time")]

    return meta, comm, time


def process_server(fn):
    reporter = f's{fn.rstrip(".json")[-1]}'
    data = load_json(fn)

    meta = {
        "PSI_DATA_SET_SIZE_LOG": data.get("PSI_DATA_SET_SIZE_LOG"),
    }

    comm = [
        {
            "reporter": reporter,
            "session": "c" if key == "client" else key,
            "sent": val.get("sent"),
            "recv": val.get("recv"),
        }
        for key, val in data.get("comm").items()
    ]

    time = [
        {"reporter": reporter, **t}
        for t in chain(data.get("time_host"), data.get("time_enclave"))
    ]

    return meta, comm, time


if __name__ == "__main__":
    import sys

    data_files = sorted(glob(f"{sys.argv[1]}/2021*.json"))

    pool = []

    for test_id, reports in groupby(data_files, lambda fn: Path(fn).name.split("-")[0]):

        meta, comm, time = process_client(next(reports))
        for s in reports:
            m, c, t = process_server(s)
            meta.update(m)
            comm.extend(c)
            time.extend(t)

        pool.append({"test_id": test_id, "meta": meta, "comm": comm, "time": time})

    fn = f"{uuid1()}.json"
    with open(fn, "w") as f:
        json.dump(pool, f)

    print("result written to", str(Path(fn).absolute()))
