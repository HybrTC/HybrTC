#include <chrono>
#include <cstddef>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "psi_context.hpp"
#include "spdlog/spdlog.h"
#include "timer.hpp"
#include "utils/spdlog.hpp"
#include "utils/zmq.hpp"

using nlohmann::json;
using std::string;
using zmq::context_t;
using zmq::socket_t;

static auto attestation_servant(Socket& server, PSIContext& context) -> u32
{
    auto request = server.recv();
    SPDLOG_DEBUG("handle_attestation_req: request received");
    assert(request["type"].get<MessageType>() == AttestationRequest);
    auto payload = request["payload"].get<v8>();

    auto response = context.handle_attestation_req(payload);
    assert(response["type"].get<MessageType>() == AttestationResponse);
    server.send(response);
    SPDLOG_DEBUG("handle_attestation_req: response sent");

    return response["sid"].get<u32>();
}

auto client_servant(int port, context_t* io, PSIContext* context)
{
    SPDLOG_INFO("starting {} at port {}", __FUNCTION__, port);

    /* construct a response socket and bind to interface */
    auto server = Socket::listen(*io, port);

    /* attestation */
    auto sid = attestation_servant(server, *context);
    context->set_client_sid(sid);
    SPDLOG_DEBUG("server session from client: sid={:08x}", sid);

    /* compute query */
    {
        auto request = server.recv();
        SPDLOG_DEBUG("handle_query_request: request received");
        assert(request["type"].get<MessageType>() == QueryRequest);
        if (request["sid"].get<u32>() != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        auto payload = request["payload"].get<v8>();

        auto response = context->handle_query_request(sid, payload);
        assert(response["type"].get<MessageType>() == QueryResponse);
        server.send(response);
        SPDLOG_DEBUG("handle_query_request: response sent");
    }

    return server.statistics();
}

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
auto peer_servant(int port, context_t* io, PSIContext* context)
{
    SPDLOG_INFO("starting {} at port {}", __FUNCTION__, port);

    /* construct a response socket and bind to interface */
    auto server = Socket::listen(*io, port);

    /* attestation */
    auto sid = attestation_servant(server, *context);
    context->set_peer_isid(sid);
    SPDLOG_DEBUG("server session from peer: sid={:08x}", sid);

    /* compute query */
    {
        auto request = server.recv();
        SPDLOG_DEBUG("handle_compute_req: request received");
        assert(request["type"].get<MessageType>() == ComputeRequest);
        if (request["sid"].get<u32>() != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        auto payload = request["payload"].get<v8>();

        auto response = context->handle_compute_req(sid, payload);
        assert(response["type"].get<MessageType>() == ComputeResponse);
        server.send(response);
        SPDLOG_DEBUG("handle_compute_req: response sent");
    }

    return server.statistics();
}

auto peer_client(const char* peer_endpoint, context_t* io, PSIContext* context)
{
    SPDLOG_INFO("starting {} to {}", __FUNCTION__, peer_endpoint);

    /* construct a request socket and connect to interface */
    auto client = Socket::connect(*io, peer_endpoint);

    /* attestation */
    auto request = context->prepare_attestation_req();
    assert(request["type"].get<MessageType>() == AttestationRequest);
    client.send(request);
    SPDLOG_DEBUG("prepare_attestation_req: request sent");

    auto response = client.recv();
    SPDLOG_DEBUG("process_attestation_resp: response received");
    assert(response["type"].get<MessageType>() == AttestationResponse);
    auto payload = response["payload"].get<v8>();
    auto sid = context->process_attestation_resp(payload);
    if (response["sid"].get<u32>() != sid)
    {
        throw std::runtime_error("the sid received and generated don't match");
    }

    context->set_peer_osid(sid);
    SPDLOG_DEBUG("server session to peer: sid={:08x}", sid);

    /* build and send bloom filter */
    {
        auto request = context->prepare_compute_req();
        assert(request["type"].get<MessageType>() == ComputeRequest);
        client.send(request);
        SPDLOG_DEBUG("prepare_compute_req: request sent");
    }

    /* get match result and aggregate */
    {
        auto response = client.recv();
        SPDLOG_DEBUG("process_compute_resp: response received");
        assert(response["type"].get<MessageType>() == ComputeResponse);
        if (response["sid"].get<u32>() != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        auto payload = response["payload"].get<v8>();
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
    app.add_option("-e,--enclave-path", enclave_image_path, "path to the signed enclave image")
        ->required()
        ->check(CLI::ExistingFile);

    bool server_id;
    app.add_option("-i,--server-id", server_id, "server id: 0 or 1")->required();

    size_t log_data_size;
    app.add_option("-l,--data-size", log_data_size, "logarithm of data set size")->required();

    int client_port;
    app.add_option("-c,--client-port", client_port, "listening port for client to connect")->required();

    int peer_port;
    app.add_option("-p,--peer-port", peer_port, "listening port for peer to connect")->required();

    string peer_endpoint;
    app.add_option("-s,--peer-endpoint", peer_endpoint, "peer's endpoint")->required();

    string test_id = fmt::format("{:%Y%m%dT%H%M%S}", fmt::localtime(time(nullptr)));
    app.add_option("--test-id", test_id, "test identifier");

    CLI11_PARSE(app, argc, argv);

    /* configure logger */

    const string pattern = fmt::format("%^[%Y-%m-%d %H:%M:%S.%e] [%L] [s{}] [%t] %s:%# -%$ %v", int(server_id));

    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern(pattern);

    /* initialize the zmq context with 2 IO thread */
    context_t context(1);

    /* initialize PSI context */
    PSIContext psi(enclave_image_path.c_str(), (1 << log_data_size), (1 << (log_data_size * 3 / 2)), server_id);

    Timer timer;
    timer("start");

    /* start server */
    auto s_client = std::async(std::launch::async, client_servant, client_port, &context, &psi);

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    auto s_peer = std::async(std::launch::async, peer_servant, peer_port, &context, &psi);

    /* wait for the server starting up */
    std::this_thread::sleep_for(std::chrono::seconds(1));

    /* start client */
    auto [c_peer_sent, c_peer_recv] = peer_client(peer_endpoint.c_str(), &context, &psi);

    /* finish everything */
    auto [s_peer_sent, s_peer_recv] = s_peer.get();
    SPDLOG_INFO("Server for peer closed");
#endif

    auto [s_client_sent, s_client_recv] = s_client.get();
    SPDLOG_INFO("Server for client closed");

    timer("done");

    json output = json::object(
        {
            {"PSI_DATA_SET_SIZE_LOG", log_data_size},
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
                {"c/p:sent", c_peer_sent}, {"c/p:recv", c_peer_recv}, {"s/p:sent", s_peer_sent},
                {"s/p:recv", s_peer_recv},
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
