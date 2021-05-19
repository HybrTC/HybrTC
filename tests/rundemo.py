#! /usr/bin/env python3.8

import argparse
import asyncio
import os
from datetime import datetime
from itertools import product
from pathlib import Path
from signal import SIGKILL
from time import sleep
from uuid import uuid1

SERVER0_HOST = "localhost"
SERVER0_PORT_P = "5000"
SERVER0_PORT_C = "5001"

SERVER1_HOST = "localhost"
SERVER1_PORT_P = "6000"
SERVER1_PORT_C = "6001"

NET_TOPO = {
    "server0": {
        "client_port": SERVER0_PORT_C,
        "peer_port": SERVER0_PORT_P,
        "peer_endpoint": f"tcp://{SERVER1_HOST}:{SERVER1_PORT_P}",
    },
    "server1": {
        "client_port": SERVER1_PORT_C,
        "peer_port": SERVER1_PORT_P,
        "peer_endpoint": f"tcp://{SERVER0_HOST}:{SERVER0_PORT_P}",
    },
    "client": {
        "s0_endpoint": f"tcp://{SERVER0_HOST}:{SERVER0_PORT_C}",
        "s1_endpoint": f"tcp://{SERVER1_HOST}:{SERVER1_PORT_C}",
    },
}

pid = {
    "server0": 0,
    "server1": 0,
    "client": 0,
}


async def run_client(client_path, test_id, s0_endpoint, s1_endpoint):
    cmd = [
        str(client_path),
        f"--s0-endpoint={s0_endpoint}",
        f"--s1-endpoint={s1_endpoint}",
        f"--test-id={test_id}",
    ]

    print(*cmd)

    sleep(1)
    proc = await asyncio.create_subprocess_exec(*cmd)
    pid["client"] = proc.pid

    await proc.wait()

    if proc.returncode != 0:
        raise RuntimeError(f"Client returns {proc.returncode}")


async def run_server(server_path, test_id, server_id, data_size, enclave_path, client_port, peer_port, peer_endpoint):
    cmd = [
        str(server_path),
        f"--enclave-path={enclave_path}",
        f"--server-id={server_id}",
        f"--data-size={data_size}",
        f"--client-port={client_port}",
        f"--peer-port={peer_port}",
        f"--peer-endpoint={peer_endpoint}",
        f"--test-id={test_id}",
    ]

    print(*cmd)
    proc = await asyncio.create_subprocess_exec(*cmd)
    pid[f"server{server_id}"] = proc.pid

    await proc.wait()

    if proc.returncode != 0:
        raise RuntimeError(f"Server{server_id} returns {proc.returncode}")


async def test(client: Path, server: Path, enclave: Path, data_size: int):
    test_id = datetime.now().strftime("%Y%m%dT%H%M%S")

    procs = {
        "server0": run_server(server, test_id, 0, data_size, enclave, **NET_TOPO["server0"]),
        "server1": run_server(server, test_id, 1, data_size, enclave, **NET_TOPO["server1"]),
        "client": run_client(client, test_id, **NET_TOPO["client"]),
    }

    try:
        await asyncio.gather(*procs.values())
    except BaseException as e:
        arguments = {"client": client, "server": server, "enclave": enclave, "data_size": data_size}
        print(arguments)
        print(e)
        for p in pid.values():
            try:
                os.kill(p, SIGKILL)
            except ProcessLookupError:
                pass


async def main(args):
    CLIENT_DIR: Path = args.build / "client"
    SERVER_DIR: Path = args.build / "server/host"
    ENCLAVE_DIR: Path = args.build / "server/enclave"

    for select, aggregate, size in product(args.select, args.aggregate, args.size):
        if aggregate == "0x00" and size == 20:
            continue

        client = CLIENT_DIR / f"client-{select}-{aggregate}"
        server = SERVER_DIR / f"server-{select}-{aggregate}"
        enclave = ENCLAVE_DIR / f"enclave-{select}-{aggregate}.signed"

        assert client.exists()
        assert server.exists()
        assert enclave.exists()

        for i in range(args.repeat):
            print("************************************************************")
            print(f"*    select={select} aggregate={aggregate} size={size} {i}/{args.repeat}")
            print("************************************************************")
            await test(client, server, enclave, size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--binary-dir", dest="build", type=Path, required=True)
    parser.add_argument("--repeat", dest="repeat", type=int, default=1)
    parser.add_argument("--select-policy", dest="select", nargs="+", required=True)
    parser.add_argument("--aggregate-policy", dest="aggregate", nargs="+", required=True)
    parser.add_argument("--data-size", dest="size", type=int, default=[10], nargs="+")

    args = parser.parse_args()

    asyncio.run(main(args))
