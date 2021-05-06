#include <chrono>
#include <future>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>
#include <spdlog.hpp>
#include <zmq.hpp>

#include "common/types.hpp"
#include "psi_context.hpp"
#include "zmq_utils.hpp"

using nlohmann::json;

#define LOGGER "consolse"

static auto attestation_servant(zmq::socket_t& server, PSIContext& context)
    -> uint32_t
{
    json request = recv(server);
    assert(request["type"].get<MessageType>() == AttestationRequest);
    auto payload = request["payload"].get<v8>();

    json response = context.handle_attestation_req(payload);
    assert(response["type"].get<MessageType>() == AttestationResponse);
    send(server, response);

    return response["sid"].get<uint32_t>();
}

void client_servant(int port, zmq::context_t* io, PSIContext* context)
{
    /* construct a router socket and bind to interface */
    zmq::socket_t server = listen(*io, port);

    /* attestation */
    context->set_client_sid(attestation_servant(server, *context));

    /* compute query */
    json request = recv(server);
    assert(request["type"].get<MessageType>() == QueryRequest);
    auto sid = request["sid"].get<uint32_t>();
    auto payload = request["payload"].get<v8>();

    json response = context->handle_query_request(sid, payload);
    assert(response["type"].get<MessageType>() == QueryResponse);
    send(server, response);
}

void peer_servant(int port, zmq::context_t* io, PSIContext* context)
{
    /* construct a router socket and bind to interface */
    zmq::socket_t server = listen(*io, port);

    /* attestation */
    context->set_peer_isid(attestation_servant(server, *context));

    /* compute query */
    {
        json request = recv(server);
        assert(request["type"].get<MessageType>() == ComputeRequest);
        auto sid = request["sid"].get<uint32_t>();
        auto payload = request["payload"].get<v8>();

        json response = context->handle_query_request(sid, payload);
        assert(response["type"].get<MessageType>() == ComputeResponse);
        send(server, response);
    }
}

void peer_client(
    const char* peer_endpoint,
    zmq::context_t* io,
    PSIContext* context)
{
    // construct a request socket and connect to interface
    zmq::socket_t client = connect(*io, peer_endpoint);

    /* attestation */
    {
        json request = context->prepare_attestation_req();
        assert(request["type"].get<MessageType>() == AttestationRequest);
        send(client, request);

        json response = recv(client);
        assert(request["type"].get<MessageType>() == AttestationResponse);
        auto sid = request["sid"].get<uint32_t>();
        auto payload = request["payload"].get<v8>();
        context->set_peer_osid(context->process_attestation_resp(sid, payload));
    }

    /* build and send bloom filter */
    json request = context->prepare_compute_req();
    assert(request["type"].get<MessageType>() == ComputeRequest);
    send(client, request);

    /* get match result and aggregate */
    json response = recv(client);
    assert(request["type"].get<MessageType>() == ComputeResponse);
    auto sid = request["sid"].get<uint32_t>();
    auto payload = request["payload"].get<v8>();
    context->process_compute_resp(sid, payload);
}

auto main(int argc, const char* argv[]) -> int
{
    auto log = spdlog::stdout_color_mt(LOGGER);
    log->set_level(spdlog::level::debug);

    if (argc != 6)
    {
        fprintf(
            stderr,
            "Usage: %s <server_id> <client_port> <peer_port> <peer_endpoint> "
            "<enclave_image_path>\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    const int server_id = std::stoi(argv[1], nullptr, 0);
    const int client_port = std::stoi(argv[2], nullptr, 0);
    const int peer_port = std::stoi(argv[3], nullptr, 0);
    const char* peer_endpoint = argv[4];
    const char* enclave_image_path = argv[5];

    if (server_id != 0 && server_id != 1)
    {
        log->error("unexpected server id {}: it can only be 0 or 1", server_id);
        exit(EXIT_FAILURE);
    }
    else
    {
        log->info(
            "server_id={} port={}/{} peer_endpoint={}",
            server_id,
            client_port,
            peer_port,
            peer_endpoint);
    }

    /* initialize the zmq context with 2 IO thread */
    zmq::context_t context(1);

    /* initialize PSI context */
    PSIContext psi(enclave_image_path, bool(server_id));

    /* start server */
    auto s_peer =
        std::async(std::launch::async, peer_servant, peer_port, &context, &psi);
    auto s_client = std::async(
        std::launch::async, client_servant, client_port, &context, &psi);

    /* wait for the server starting up */
    std::this_thread::sleep_for(std::chrono::seconds(1));

    /* start client */
    auto c_peer = std::async(
        std::launch::async, peer_client, peer_endpoint, &context, &psi);

    /* finish everything */
    s_peer.wait();
    log->info("Server for peer closed");

    c_peer.wait();
    log->info("Client for peer closed");

    s_client.wait();
    log->info("Server for client closed");

    return 0;
}
