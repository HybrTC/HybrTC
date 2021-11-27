#include "attestation.h"

#include "common/types.hpp"
#include "host/spdlog.hpp"

auto attestation_servant(TxSocket& server, PSIContext& context) -> u32
{
    auto request = server.recv();
    SPDLOG_DEBUG("handle_attestation_req: request received");
    if (request->message_type != Message::AttestationRequest)
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

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
auto attestation_initiator(TxSocket& client, PSIContext& context) -> u32
{
    auto request = context.prepare_attestation_req();
    assert(request->message_type == AttestationRequest);
    client.send(*request);
    SPDLOG_DEBUG("prepare_attestation_req: request sent");

    auto response = client.recv();
    SPDLOG_DEBUG("process_attestation_resp: response received");
    assert(response.message_type == AttestationResponse);
    auto sid = context.process_attestation_resp(response->payload, response->payload_len);

    if (response->session_id != sid)
    {
        throw std::runtime_error("the sid received and generated don't match");
    }

    return sid;
}
#endif
