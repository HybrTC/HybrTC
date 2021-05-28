import json
from functools import reduce
from glob import glob
from itertools import groupby
from pathlib import Path

import pandas as pd


def load_json(fn):
    return json.loads(Path(fn).read_bytes())


def pprint(obj):
    return json.dumps(obj, indent=True)


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

LABELS = [
    "initiate attestation",
    "initiate query",
    "result received",
]


def process_client(fn):
    data = load_json(fn)
    timer = dict((t["name"], t["clock"]) for t in data.get("time"))
    return {
        "PSI_PAILLIER_PK_LEN": data.get("PSI_PAILLIER_PK_LEN"),
        "PSI_MELBOURNE_P": data.get("PSI_MELBOURNE_P"),
        "PSI_SELECT_POLICY": SEL[data.get("PSI_SELECT_POLICY")],
        "PSI_AGGREGATE_POLICY": AGG[data.get("PSI_AGGREGATE_POLICY")],
        "c:c/s0:sent": data.get("c/s0:sent"),
        "c:c/s0:recv": data.get("c/s0:recv"),
        "c:c/s1:sent": data.get("c/s1:sent"),
        "c:c/s1:recv": data.get("c/s1:recv"),
        "c:duration": timer["done"] - timer["start"],
        "c:s0:attest": timer[f"c/s0: {LABELS[1]}"] - timer[f"c/s0: {LABELS[0]}"],
        "c:s0:query": timer[f"c/s0: {LABELS[2]}"] - timer[f"c/s0: {LABELS[1]}"],
        "c:s1:attest": timer[f"c/s1: {LABELS[1]}"] - timer[f"c/s1: {LABELS[0]}"],
        "c:s1:query": timer[f"c/s1: {LABELS[2]}"] - timer[f"c/s1: {LABELS[1]}"],
    }


def process_server(fn, sid):
    def calc_duration(timer):
        return timer["done"] - timer["start"]

    data = load_json(fn)
    ret = {
        f"s{sid}:PSI_DATA_SET_SIZE_LOG": data.get("PSI_DATA_SET_SIZE_LOG"),
        f"s{sid}:c/p:sent": data.get("c/p:sent"),
        f"s{sid}:c/p:recv": data.get("c/p:recv"),
        f"s{sid}:s/p:sent": data.get("s/p:sent"),
        f"s{sid}:s/p:recv": data.get("s/p:recv"),
        f"s{sid}:s/c:sent": data.get("s/c:sent"),
        f"s{sid}:s/c:recv": data.get("s/c:recv"),
    }

    for _, v in groupby(
        sorted(data.get("enclave_timer"), key=lambda item: item["thread"]),
        lambda item: item["thread"],
    ):
        thread_timer = dict(
            (
                k,
                calc_duration(dict((item["name"].split(":")[1], item["clock"]) for item in v)),
            )
            for k, v in groupby(v, lambda item: item["name"].split(":")[0])
        )

        prefix = f"s{sid}"
        if "aggregate" in thread_timer:
            prefix = f"s{sid}:a"

        if "get_result" in thread_timer:
            prefix = f"s{sid}:c"

        if "match_bloom_filter" in thread_timer:
            prefix = f"s{sid}:p"

        thread_timer = dict((f"{prefix}:{k}", v) for k, v in thread_timer.items())
        ret.update(thread_timer)

    return ret


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


if __name__ == "__main__":
    import sys

    data_files = sorted(glob(f"{sys.argv[1]}/2021*.json"))
    data_files = [(k, tuple(v)) for k, v in groupby(data_files, lambda fn: fn.split("-")[0])]

    df = pd.DataFrame(
        [
            {
                **process_client(c),
                **process_server(s0, 0),
                **process_server(s1, 1),
            }
            for test, (c, s0, s1) in data_files
        ]
    )

    data = df.copy()

    data["SIZE"] = data["s0:PSI_DATA_SET_SIZE_LOG"]
    data = data.fillna(0)
    # data = drop_outliner(data, ATTRIBUTES, FEATURES_COMM + FEATURES_TIME, 3)

    df_comm = data[ATTRIBUTES + FEATURES_COMM].copy()
    stat_comm = df_comm.groupby(ATTRIBUTES).mean()

    df_time = data[ATTRIBUTES + FEATURES_TIME].copy()
    stat_time = df_time.groupby(ATTRIBUTES).mean()

    print(df[["s0:c:set_client_query", "s1:c:set_client_query"]] / 1000000)
