#include <mutex>
#include "common/types.hpp"
#include "config.hpp"
#include "enclave_context.hpp"

#include "helloworld_t.h"
#include "msg.pb.h"
#include "sgx/log.h"

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
#include "psi/select_handler.hpp"
sptr<SelectHandler> handler;
#else
#include "psi/join_handler.hpp"
sptr<JoinHandler> handler;
#endif

sptr<EnclaveContext> global;

static struct
{
    std::mutex attester;
    std::mutex verifier;
} locks;

static struct
{
    unsigned client = -1;
    unsigned peer_prev = -1;
    unsigned peer_next = -1;
} session_id;

void initialize(unsigned server_id, unsigned server_count)
{
    TRACE_ENCLAVE("Initializing server %u/%u", server_id, server_count);
    if (global == nullptr)
    {
        global = std::make_shared<EnclaveContext>(server_id, server_count);
    }
}

void verifier_generate_challenge(u8** obuf, size_t* olen)
{
    locks.verifier.lock();
    global->verifier_generate_challenge(obuf, olen);
    locks.verifier.unlock();
}

auto attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    locks.attester.lock();
    auto sid = global->attester_generate_response(ibuf, ilen, obuf, olen);
    locks.attester.unlock();
    if ((sid & 0x00ff0000) == 0x00ff0000)
    {
        session_id.client = sid;
    }
    else
    {
        session_id.peer_prev = sid;
    }
    return sid;
}

auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    locks.verifier.lock();
    auto sid = global->verifier_process_response(ibuf, ilen);
    TRACE_ENCLAVE("sid generated: %08x", sid);
    locks.verifier.unlock();
    session_id.peer_next = sid;
    return sid;
}

void set_client_query(const u8* ibuf, size_t ilen, const u32* data_key, const u32* data_val, size_t data_size)
{
    const uint32_t server_id = global->server_id();
    const uint32_t server_count = global->server_count();

    handler = std::make_shared<decltype(handler)::element_type>(global->rand_ptr());

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    (void)(ibuf);
    (void)(ilen);
    (void)(half);
#else
    hybrtc::QueryRequest request;
    request.ParseFromString(global->session(session_id.client).cipher().decrypt_str(ibuf, ilen));

    if (request.server_id() != server_id)
    {
        TRACE_ENCLAVE("Server ID mismatch: given %u, requested %u", server_id, request.server_id());
        abort();
    }
    else
    {
        handler->set_id(server_id);
    }
    if (request.server_count() != server_count)
    {
        TRACE_ENCLAVE("Server ID mismatch: given %u, requested %u", server_count, request.server_count());
        abort();
    }
    else
    {
        handler->set_count(server_count);
    }
    handler->set_public_key(request.homo_pk());
#endif

    handler->load_data(data_key, data_val, data_size);
}

void gen_compute_request(u8** obuf, size_t* olen)
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    auto output = handler->build_filter();
    global->dump_enc(session_id.peer_next, output, obuf, olen);
#else
    (void)(obuf);
    (void)(olen);

    TRACE_ENCLAVE("UNREACHABLE CODE");
    abort();
#endif
}

auto pro_compute_request(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> int
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    const auto input = global->session(session_id.peer_prev).cipher().decrypt_str(ibuf, ilen);
    std::string output;
    auto otype = handler->match_filter(input, output);
    if (otype == Message::ComputeRequest)
    {
        global->dump_enc(session_id.peer_next, output, obuf, olen);
    }
    else if (otype == Message::ComputeResponse)
    {
        global->dump_enc(session_id.peer_prev, output, obuf, olen);
    }
    else
    {
        TRACE_ENCLAVE("Invalid response returned by %s", __FUNCTION__);
        abort();
    }

    return otype;
#else
    (void)(sid);
    (void)(ibuf);
    (void)(ilen);
    (void)(obuf);
    (void)(olen);

    TRACE_ENCLAVE("UNREACHABLE CODE");
    abort();
#endif
}

void pro_compute_response(const u8* ibuf, size_t ilen)
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    const auto input = global->session(session_id.peer_next).cipher().decrypt_str(ibuf, ilen);
    handler->build_result(input);
#else
    (void)(sid);
    (void)(ibuf);
    (void)(ilen);

    TRACE_ENCLAVE("UNREACHABLE CODE");
    abort();
#endif
}

void get_result(u8** obuf, size_t* olen)
{
    global->dump_enc(session_id.client, handler->get_result(), obuf, olen);
}
