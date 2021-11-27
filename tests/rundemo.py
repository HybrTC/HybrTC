#! /usr/bin/env python3.8

import argparse
import json
import os
from datetime import datetime
from itertools import product
from pathlib import Path
from signal import SIGKILL
from time import sleep


SERVERS = [
    {
        "host": "127.0.0.1",
        "port_p": 5000,
        "port_c": 5001,
    },
    {
        "host": "127.0.0.1",
        "port_p": 6000,
        "port_c": 6001,
    },
]


CLIENT_TOPO = json.dumps([{"host": s["host"], "port": s["port_c"]} for s in SERVERS])
SERVER_TOPO = json.dumps([{"host": s["host"], "port": s["port_p"]} for s in SERVERS])


def prefix(pid):
    return f"[{datetime.now().isoformat()}] [{pid}]"


def run_client(client_path, test_id):
    cmd = [
        str(client_path),
        f"--topo={CLIENT_TOPO}",
        f"--test-id={test_id}",
    ]

    pid = os.fork()
    if pid > 0:
        print(prefix(pid), *cmd)
        return pid

    sleep(4)
    os.execv(cmd[0], cmd)


def run_server(server_path, test_id, server_id, data_size, enclave_path):

    client_port = SERVERS[server_id]["port_c"]

    cmd = [
        str(server_path),
        f"--enclave-path={enclave_path}",
        f"--server-id={server_id}",
        f"--data-size={data_size}",
        f"--listen={client_port}",
        f"--peers={SERVER_TOPO}",
        f"--test-id={test_id}",
    ]

    pid = os.fork()
    if pid > 0:
        print(prefix(pid), *cmd)
        return pid

    os.execv(cmd[0], cmd)


def test(client: Path, server: Path, enclave: Path, data_size: int):
    test_id = datetime.now().strftime("%Y%m%dT%H%M%S")

    procs = {
        run_server(server, test_id, 0, data_size, enclave): "Server0",
        run_server(server, test_id, 1, data_size, enclave): "Server1",
        run_client(client, test_id): "Client",
    }

    while len(procs) > 0:
        (pid, status) = os.wait()
        if pid not in procs:
            print("unknown process", pid)
            continue

        name = procs[pid]
        del procs[pid]

        if os.WIFEXITED(status):
            if os.WEXITSTATUS(status) == 0:
                print(prefix(pid), name, "exited with return code 0")
                continue
            else:
                print(
                    prefix(pid), name, "exited with return code", os.WEXITSTATUS(status)
                )

        if os.WCOREDUMP(status):
            print(prefix(pid), name, "exited with WCOREDUMP")

        if os.WIFSIGNALED(status):
            print(prefix(pid), name, "exited with WIFSIGNALED", os.WTERMSIG(status))

        arguments = {
            "client": client,
            "server": server,
            "enclave": enclave,
            "data_size": data_size,
        }
        print(prefix(pid), arguments)

        for p in procs.keys():
            try:
                os.kill(p, SIGKILL)
            except ProcessLookupError:
                pass

        break

    output_file = [
        f"{test_id}-client.json",
        f"{test_id}-server0.json",
        f"{test_id}-server1.json",
    ]

    if not all(map(Path.exists, map(Path, output_file))):
        exit(-1)


def main(args):
    CLIENT_DIR: Path = args.build / "src/client"
    SERVER_DIR: Path = args.build / "src/server/host"
    ENCLAVE_DIR: Path = args.build / "src/server/enclave"

    test_suite = list(product(args.size, args.select, args.aggregate))
    total = len(test_suite)
    repeat = args.repeat

    for i in range(repeat):
        for idx, (size, select, aggregate) in enumerate(test_suite):
            if aggregate == "0x00" and size == 20:
                continue

            client = CLIENT_DIR / f"client-{select}-{aggregate}"
            server = SERVER_DIR / f"server-{select}-{aggregate}"
            enclave = ENCLAVE_DIR / f"enclave-{select}-{aggregate}.signed"

            assert client.exists()
            assert server.exists()
            assert enclave.exists()

            print("************************************************************")
            print(
                f"*    {i}/{repeat} # {idx}/{total} # size={size} select={select} aggregate={aggregate}"
            )
            print("************************************************************")
            test(client, server, enclave, size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--binary-dir", dest="build", type=Path, required=True)
    parser.add_argument("--repeat", dest="repeat", type=int, default=1)
    parser.add_argument("--select-policy", dest="select", nargs="+", required=True)
    parser.add_argument(
        "--aggregate-policy", dest="aggregate", nargs="+", required=True
    )
    parser.add_argument("--data-size", dest="size", type=int, default=[10], nargs="+")

    args = parser.parse_args()

    main(args)
