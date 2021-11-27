#include "routine.h"

#include "attestation.h"
#include "host/TxSocket.hpp"

auto client_thread(int port, PSIContext* context) -> std::pair<size_t, size_t>
{
    SPDLOG_INFO("starting {}: serving at port {}", __FUNCTION__, port);

    /* construct a response socket and bind to interface */
    auto server = TxSocket::listen(port);
    server.accept();

    /* attestation */
    auto sid = attestation_servant(server, *context);
    context->set_client_sid(sid);
    SPDLOG_DEBUG("server session from client: sid={:08x}", sid);

    /* compute query */
    {
        auto request = server.recv();
        SPDLOG_DEBUG("handle_query_request: request received");
        if (request->message_type != Message::QueryRequest)
        {
            std::abort();
        }
        if (request->session_id != sid)
        {
            throw std::runtime_error("session id doesn't match");
        }
        v8 payload(request->payload, request->payload + request->payload_len);

        auto response = context->handle_query_request(sid, payload);
        assert(response->message_type == Message::QueryResponse);
        server.send(*response);
        SPDLOG_DEBUG("handle_query_request: response sent");
    }

    return server.statistics();
}
