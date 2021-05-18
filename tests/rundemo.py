import argparse
import subprocess
from itertools import product
from pathlib import Path
from datetime import datetime
from uuid import uuid1


def prefix():
    return datetime.now().strftime("%Y%m%dT%H%M%S")


SERVER0_HOST = "localhost"
SERVER0_PORT_P = "5000"
SERVER0_PORT_C = "5001"

SERVER1_HOST = "localhost"
SERVER1_PORT_P = "6000"
SERVER1_PORT_C = "6001"

NETWORK_TOPOLOGY = {
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


def run_client(client_path, test_id, s0_endpoint, s1_endpoint):
    return subprocess.Popen(
        [str(client_path), f"--s0-endpoint={s0_endpoint}", f"--s1-endpoint={s1_endpoint}", f"--test-id={test_id}"],
    )


def run_server(server_path, test_id, server_id, data_size, enclave_path, client_port, peer_port, peer_endpoint):
    return subprocess.Popen(
        [
            str(server_path),
            f"--enclave-path={enclave_path}",
            f"--server-id={server_id}",
            f"--data-size={data_size}",
            f"--client-port={client_port}",
            f"--peer-port={peer_port}",
            f"--peer-endpoint={peer_endpoint}",
            f"--test-id={test_id}",
        ],
    )


def test(client: Path, server: Path, enclave: Path, data_size: int):
    test_id = prefix()

    processes = {
        "client": run_client(client, test_id, **NETWORK_TOPOLOGY["client"]),
        "server0": run_server(server, test_id, 0, data_size, enclave, **NETWORK_TOPOLOGY["server0"]),
        "server1": run_server(server, test_id, 1, data_size, enclave, **NETWORK_TOPOLOGY["server1"]),
    }

    for name, proc in processes.items():
        proc.wait()
        if proc.returncode != 0:
            arguments = {"client": client, "server": server, "enclave": enclave, "data_size": data_size}
            raise RuntimeError(f"{arguments} / {name} => {proc.returncode}")


def main(args):
    CLIENT_DIR: Path = args.build / "client"
    SERVER_DIR: Path = args.build / "server/host"
    ENCLAVE_DIR: Path = args.build / "server/enclave"

    for select, aggregate, size in product(args.select, args.aggregate, args.size):
        client = CLIENT_DIR / f"client-{select}-{aggregate}"
        server = SERVER_DIR / f"server-{select}-{aggregate}"
        enclave = ENCLAVE_DIR / f"enclave-{select}-{aggregate}.signed"

        assert client.exists()
        assert server.exists()
        assert enclave.exists()

        for i in range(args.repeat):
            print(f"select={select} aggregate={aggregate} size={size} {i}/{args.repeat}")
            test(client, server, enclave, size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--binary-dir", dest="build", type=Path, required=True)
    parser.add_argument("--repeat", dest="repeat", type=int, default=1)
    parser.add_argument("--select-policy", dest="select", nargs="+", required=True)
    parser.add_argument("--aggregate-policy", dest="aggregate", nargs="+", required=True)
    parser.add_argument("--data-size", dest="size", type=int, default=[10], nargs="+")

    args = parser.parse_args()

    main(args)
