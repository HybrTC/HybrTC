#include <chrono>
#include <future>
#include <string>
#include <thread>

#include "common/types.hpp"
#include "psi_context.hpp"
#include "utils/spdlog.hpp"
#include "utils/zmq.hpp"

using std::stoi;
using std::string;
using zmq::context_t;
using zmq::socket_t;

static auto attestation_servant(socket_t& server, PSIContext& context) -> u32
{
    auto request = recv(server);
    SPDLOG_DEBUG("handle_attestation_req: request received");
    assert(request["type"].get<MessageType>() == AttestationRequest);
    auto payload = request["payload"].get<v8>();

    auto response = context.handle_attestation_req(payload);
    assert(response["type"].get<MessageType>() == AttestationResponse);
    send(server, response);
    SPDLOG_DEBUG("handle_attestation_req: response sent");

    return response["sid"].get<u32>();
}

void client_servant(int port, context_t* io, PSIContext* context)
{
    SPDLOG_DEBUG("starting {} at port {}", __FUNCTION__, port);

    /* construct a router socket and bind to interface */
    socket_t server = listen(*io, port);

    /* attestation */
    context->set_client_sid(attestation_servant(server, *context));

    /* compute query */
    auto request = recv(server);
    SPDLOG_DEBUG("handle_query_request: request received");
    assert(request["type"].get<MessageType>() == QueryRequest);
    auto sid = request["sid"].get<u32>();
    auto payload = request["payload"].get<v8>();

    auto response = context->handle_query_request(sid, payload);
    assert(response["type"].get<MessageType>() == QueryResponse);
    send(server, response);
    SPDLOG_DEBUG("handle_query_request: response sent");
}

#ifndef PSI_SELECT_ONLY
void peer_servant(int port, context_t* io, PSIContext* context)
{
    SPDLOG_DEBUG("starting {} at port {}", __FUNCTION__, port);

    /* construct a router socket and bind to interface */
    auto server = listen(*io, port);

    /* attestation */
    context->set_peer_isid(attestation_servant(server, *context));

    /* compute query */
    {
        auto request = recv(server);
        SPDLOG_DEBUG("handle_compute_req: request received");
        assert(request["type"].get<MessageType>() == ComputeRequest);
        auto sid = request["sid"].get<u32>();
        auto payload = request["payload"].get<v8>();

        auto response = context->handle_compute_req(sid, payload);
        assert(response["type"].get<MessageType>() == ComputeResponse);
        send(server, response);
        SPDLOG_DEBUG("handle_compute_req: response sent");
    }
}

void peer_client(const char* peer_endpoint, context_t* io, PSIContext* context)
{
    SPDLOG_DEBUG("starting {} to {}", __FUNCTION__, peer_endpoint);

    /* construct a request socket and connect to interface */
    auto client = connect(*io, peer_endpoint);

    /* attestation */
    {
        auto request = context->prepare_attestation_req();
        assert(request["type"].get<MessageType>() == AttestationRequest);
        send(client, request);
        SPDLOG_DEBUG("prepare_attestation_req: request sent");

        auto response = recv(client);
        SPDLOG_DEBUG("process_attestation_resp: response received");
        assert(response["type"].get<MessageType>() == AttestationResponse);
        auto sid = response["sid"].get<u32>();
        auto payload = response["payload"].get<v8>();
        context->set_peer_osid(context->process_attestation_resp(sid, payload));
    }

    /* build and send bloom filter */
    SPDLOG_DEBUG("prepare_compute_req");
    auto request = context->prepare_compute_req();
    assert(request["type"].get<MessageType>() == ComputeRequest);
    send(client, request);
    SPDLOG_DEBUG("prepare_compute_req: request sent");

    /* get match result and aggregate */
    auto response = recv(client);
    SPDLOG_DEBUG("process_compute_resp: response received");
    assert(response["type"].get<MessageType>() == ComputeResponse);
    auto sid = response["sid"].get<u32>();
    auto payload = response["payload"].get<v8>();
    context->process_compute_resp(sid, payload);
}
#endif

auto main(int argc, const char* argv[]) -> int
{
    if (argc != 6)
    {
        fprintf(
            stderr,
            "Usage: %s <server_id> <client_port> <peer_port> <peer_endpoint> "
            "<enclave_image_path>\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    const int server_id = stoi(argv[1], nullptr, 0);
    const int client_port = stoi(argv[2], nullptr, 0);
    const int peer_port = stoi(argv[3], nullptr, 0);
    const char* peer_endpoint = argv[4];
    const char* enclave_image_path = argv[5];

    const string pattern = fmt::format(
        "%^[%Y-%m-%d %H:%M:%S.%e] [%L] [s{}] [%t] %s:%# -%$ %v", server_id);

    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern(pattern);

    if (server_id != 0 && server_id != 1)
    {
        SPDLOG_ERROR(
            "unexpected server id {}: it can only be 0 or 1", server_id);
        exit(EXIT_FAILURE);
    }
    else
    {
        SPDLOG_INFO(
            "server_id={} port={}/{} peer_endpoint={}",
            server_id,
            client_port,
            peer_port,
            peer_endpoint);
    }

    /* initialize the zmq context with 2 IO thread */
    context_t context(1);

    /* initialize PSI context */
    PSIContext psi(enclave_image_path, bool(server_id));

    /* start server */
    auto s_client = std::async(
        std::launch::async, client_servant, client_port, &context, &psi);

#ifndef PSI_SELECT_ONLY
    auto s_peer =
        std::async(std::launch::async, peer_servant, peer_port, &context, &psi);

    /* wait for the server starting up */
    std::this_thread::sleep_for(std::chrono::seconds(1));

    /* start client */
    peer_client(peer_endpoint, &context, &psi);

    /* finish everything */
    s_peer.wait();
    SPDLOG_INFO("Server for peer closed");
#endif

    s_client.wait();
    SPDLOG_INFO("Server for client closed");

    return 0;
}
