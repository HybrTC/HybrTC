#include "routine.h"

#include <future>
#include <mutex>

#include "attestation.h"
#include "host/TxSocket.hpp"

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT

static struct
{
    std::mutex prev;
    std::mutex next;
} lock;

static void peer_servant(TxSocket* server, TxSocket* client, PSIContext* context)
{
    server->accept();

    /* attestation */
    auto sid = attestation_servant(*server, *context);
    context->set_previous_peer_sid(sid);
    SPDLOG_DEBUG("server session from peer: sid={:08x}", sid);

    lock.prev.unlock();
    lock.next.lock();

    /* compute query */
    {
        auto request = server->recv();
        SPDLOG_DEBUG("handle_compute_req: request received");
        assert(request->message_type == Message::ComputeRequest);
        assert(request->session_id == sid);

        auto output = context->handle_compute_req(sid, request->payload, request->payload_len);
        if (output->message_type == Message::ComputeResponse)
        {
            server->send(*output);
            SPDLOG_DEBUG("handle_compute_req: response sent");
        }
        else if (output->message_type == Message::ComputeRequest)
        {
            client->send(*output);
            SPDLOG_DEBUG("handle_compute_req: requst pass by");
        }
        else
        {
            SPDLOG_ERROR("handle_compute_req: unexpected result");
            abort();
        }
    }
}

static auto peer_client(TxSocket* server, TxSocket* client, PSIContext* context)
{
    /* attestation */
    auto sid = attestation_initiator(*client, *context);
    context->set_next_peer_sid(sid);
    SPDLOG_DEBUG("client session to peer: sid={:08x}", sid);

    lock.next.unlock();
    lock.prev.lock();

    /* build and send bloom filter */
    {
        auto request = context->prepare_compute_req();
        assert(request->message_type == ComputeRequest);
        client->send(*request);
        SPDLOG_DEBUG("prepare_compute_req: request sent");
    }

    /* get match result and aggregate */
    {
        auto response = client->recv();
        SPDLOG_DEBUG("process_compute_resp: response received");
        assert(response.message_type == ComputeResponse);
        if (response->session_id != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        v8 payload(response->payload, response->payload + response->payload_len);
        context->process_compute_resp(payload);
    }

    return client->statistics();
}

auto peer_thread(uint16_t port, const char* peer_host, uint16_t peer_port, PSIContext* context)
    -> std::tuple<size_t, size_t, size_t, size_t>
{
    lock.next.lock();
    lock.prev.lock();

    SPDLOG_INFO("starting {}: serving at port {}", __FUNCTION__, port);
    auto server = TxSocket::listen(port);

    SPDLOG_INFO("starting {}: connect to {}:{}", __FUNCTION__, peer_host, peer_port);
    auto client = TxSocket::connect(peer_host, peer_port);

    /* serve for peer */
    auto s_peer = std::async(std::launch::async, peer_servant, &server, &client, context);

    /* connect to next */
    auto [c_peer_sent, c_peer_recv] = peer_client(&server, &client, context);

    /* collect statistics */
    s_peer.get();
    auto [s_peer_sent, s_peer_recv] = server.statistics();

    return std::make_tuple(c_peer_sent, c_peer_recv, s_peer_sent, s_peer_recv);
}

#endif
