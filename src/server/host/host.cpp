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

#include "common/types.hpp"
#include "host/TxSocket.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "psi_context.hpp"

using nlohmann::json;
using std::string;

static auto attestation_servant(TxSocket& server, PSIContext& context) -> u32
{
    auto request = server.recv();
    SPDLOG_DEBUG("handle_attestation_req: request received");
    if (request->message_type != AttestationRequest)
    {
        std::abort();
    }
    v8 payload(request->payload, request->payload + request->payload_len);

    auto response = context.handle_attestation_req(payload);
    assert(response->message_type == AttestationResponse);
    server.send(*response);
    SPDLOG_DEBUG("handle_attestation_req: response sent");
    return response->session_id;
}

auto client_servant(int port, PSIContext* context)
{
    SPDLOG_INFO("starting {} at port {}", __FUNCTION__, port);

    /* construct a response socket and bind to interface */
    auto server = TxSocket::listen(port);

    /* attestation */
    auto sid = attestation_servant(server, *context);
    context->set_client_sid(sid);
    SPDLOG_DEBUG("server session from client: sid={:08x}", sid);

    /* compute query */
    {
        auto request = server.recv();
        SPDLOG_DEBUG("handle_query_request: request received");
        if (request->message_type != QueryRequest)
        {
            std::abort();
        }
        if (request->session_id != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        v8 payload(request->payload, request->payload + request->payload_len);

        auto response = context->handle_query_request(sid, payload);
        assert(response->message_type == QueryResponse);
        server.send(*response);
        SPDLOG_DEBUG("handle_query_request: response sent");
    }

    return server.statistics();
}

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
auto peer_servant(int port, PSIContext* context)
{
    SPDLOG_INFO("starting {} at port {}", __FUNCTION__, port);

    /* construct a response socket and bind to interface */
    auto server = TxSocket::listen(port);

    /* attestation */
    auto sid = attestation_servant(server, *context);
    context->set_peer_isid(sid);
    SPDLOG_DEBUG("server session from peer: sid={:08x}", sid);

    /* compute query */
    {
        auto request = server.recv();
        SPDLOG_DEBUG("handle_compute_req: request received");
        if (request->message_type != ComputeRequest)
        {
            std::abort();
        }
        if (request->session_id != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        v8 payload(request->payload, request->payload + request->payload_len);

        auto response = context->handle_compute_req(sid, payload);
        assert(response->message_type == ComputeResponse);
        server.send(*response);
        SPDLOG_DEBUG("handle_compute_req: response sent");
    }

    return server.statistics();
}

auto peer_client(const char* peer_host, std::uint16_t peer_port, PSIContext* context)
{
    SPDLOG_INFO("starting {} to {}:{}", __FUNCTION__, peer_host, peer_port);

    /* construct a request socket and connect to interface */
    auto client = TxSocket::connect(peer_host, peer_port);

    /* attestation */
    auto request = context->prepare_attestation_req();
    assert(request->message_type == AttestationRequest);
    SPDLOG_DEBUG("prepare_attestation_req: request sent");
    client.send(*request);

    auto response = client.recv();
    SPDLOG_DEBUG("process_attestation_resp: response received");
    assert(response.message_type == AttestationResponse);
    v8 payload(response->payload, response->payload + response->payload_len);
    auto sid = context->process_attestation_resp(payload);
    if (response->session_id != sid)
    {
        throw std::runtime_error("the sid received and generated don't match");
    }

    context->set_peer_osid(sid);
    SPDLOG_DEBUG("server session to peer: sid={:08x}", sid);

    /* build and send bloom filter */
    {
        auto request = context->prepare_compute_req();
        assert(request->message_type == ComputeRequest);
        client.send(*request);
        // auto payload = request["payload"].get<v8>();
        // client.send(request["sid"].get<u32>(), request["type"].get<MessageType>(), payload.size(), payload.data());
        SPDLOG_DEBUG("prepare_compute_req: request sent");
    }

    /* get match result and aggregate */
    {
        auto response = client.recv();
        SPDLOG_DEBUG("process_compute_resp: response received");
        assert(response.message_type == ComputeResponse);
        if (response->session_id != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        v8 payload(response->payload, response->payload + response->payload_len);
        context->process_compute_resp(sid, payload);
    }

    return client.statistics();
}
#endif

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
    auto peer_id = (server_id + 1) % peers.size();

    /* configure logger */
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern(fmt::format("%^[%Y-%m-%d %H:%M:%S.%e] [%L] [s{}] [%t] %s:%# -%$ %v", server_id));

    /* initialize PSI context */
    PSIContext psi(
        enclave_image_path.c_str(), (1 << log_data_size), (1 << (log_data_size * 3 / 2)), server_id, peers.size());

    Timer timer;
    timer("start");

    /* start server towards client */
    auto s_client = std::async(std::launch::async, client_servant, client_port, &psi);

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    /* start server towards peer */
    auto s_peer = std::async(std::launch::async, peer_servant, peers[server_id]["port"].get<uint16_t>(), &psi);

    /* start client */
    auto [c_peer_sent, c_peer_recv] =
        peer_client(peers[peer_id]["host"].get<string>().c_str(), peers[peer_id]["port"].get<uint16_t>(), &psi);

    /* finish everything */
    auto [s_peer_sent, s_peer_recv] = s_peer.get();
    SPDLOG_INFO("Server for peer closed");

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
