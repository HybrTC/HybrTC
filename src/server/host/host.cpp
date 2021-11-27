#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <utility>

#include "common/types.hpp"
#include "host/TxSocket.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "psi_context.hpp"
#include "routine/attestation.h"
#include "routine/routine.h"

using nlohmann::json;
using std::string;

auto main(int argc, const char* argv[]) -> int
{
    /* pasrse command line argument */

    CLI::App app;

    string enclave_image_path;
    app.add_option("--enclave-path", enclave_image_path, "path to the signed enclave image")
        ->required()
        ->check(CLI::ExistingFile);

    int server_id;
    app.add_option("--server-id", server_id, "server id: 0 or 1")->required();

    size_t log_data_size;
    app.add_option("--data-size", log_data_size, "logarithm of data set size")->required();

    uint16_t client_port;
    app.add_option("--listen", client_port, "listening port for client to connect")->required();

    string topo;
    app.add_option("--peers", topo, "network topology for peer servers")->required();

    string test_id = fmt::format("{:%Y%m%dT%H%M%S}", fmt::localtime(time(nullptr)));
    app.add_option("--test-id", test_id, "test identifier");

    CLI11_PARSE(app, argc, argv);

    auto peers = json::parse(topo);

    /* configure logger */
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern(fmt::format("%^[%Y-%m-%d %H:%M:%S.%e] [%L] [s{}] [%t] %s:%# -%$ %v", server_id));

    /* initialize PSI context */
    PSIContext psi(
        enclave_image_path.c_str(), (1 << log_data_size), (1 << (log_data_size * 4 / 3)), server_id, peers.size());

    Timer timer;
    timer("start");

    /* start server towards client */
    auto s_client = std::async(std::launch::async, client_thread, client_port, &psi);

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT

    auto peer_id = (server_id + 1) % peers.size();

    auto [c_peer_sent, c_peer_recv, s_peer_sent, s_peer_recv] = peer_thread(
        peers[server_id]["port"].get<uint16_t>(),
        peers[peer_id]["host"].get<string>().c_str(),
        peers[peer_id]["port"].get<uint16_t>(),
        &psi);

#endif

    auto [s_client_sent, s_client_recv] = s_client.get();
    SPDLOG_INFO("Server for client closed");

    timer("done");

    json output = json::object({
        {"PSI_DATA_SET_SIZE_LOG", log_data_size},
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
            {"c/p:sent", c_peer_sent}, {"c/p:recv", c_peer_recv}, {"s/p:sent", s_peer_sent}, {"s/p:recv", s_peer_recv},
#endif
            {"s/c:sent", s_client_sent}, {"s/c:recv", s_client_recv}, {"host_timer", timer.to_json()},
        {
            "enclave_timer", psi.get_timer().to_json()
        }
    });

    {
        auto fn = fmt::format("{}-server{}.json", test_id, int(server_id));

        FILE* fp = std::fopen(fn.c_str(), "w");
        fputs(output.dump().c_str(), fp);
        fclose(fp);

        SPDLOG_INFO("Benchmark written to {}", fn);
    }

    return 0;
}
