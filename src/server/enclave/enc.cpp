#include <mutex>
#include "common/types.hpp"
#include "config.hpp"
#include "enclave_context.hpp"

#include "helloworld_t.h"
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
    std::mutex init;
    std::mutex attester;
    std::mutex verifier;
} locks;

static void init()
{
    locks.init.lock();
    if (global == nullptr)
    {
        global = std::make_shared<EnclaveContext>();
    }
    locks.init.unlock();
}

void verifier_generate_challenge(u8** obuf, size_t* olen)
{
    init();
    locks.verifier.lock();
    global->verifier_generate_challenge(obuf, olen);
    locks.verifier.unlock();
}

auto attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    init();
    locks.attester.lock();
    auto sid = global->attester_generate_response(ibuf, ilen, obuf, olen);
    locks.attester.unlock();
    return sid;
}

auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    locks.verifier.lock();
    auto sid = global->verifier_process_response(ibuf, ilen);
    TRACE_ENCLAVE("sid generated: %08x", sid);
    locks.verifier.unlock();
    return sid;
}

void set_client_query(
    u32 sid,
    const u8* ibuf,
    size_t ilen,
    bool half,
    const u32* data_key,
    const u32* data_val,
    size_t data_size)
{
    handler = std::make_shared<decltype(handler)::element_type>(global->rand_ptr());

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    (void)(sid);
    (void)(ibuf);
    (void)(ilen);
    (void)(half);
#else
    handler->set_public_key(global->session(sid).cipher().decrypt(ibuf, ilen));
    handler->set_half(half);
#endif

    handler->load_data(data_key, data_val, data_size);
}

void build_bloom_filter(u32 sid, u8** obuf, size_t* olen)
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    auto output = handler->build_filter();
    global->dump_enc(sid, output, obuf, olen);
#else
    (void)(sid);
    (void)(obuf);
    (void)(olen);

    TRACE_ENCLAVE("UNREACHABLE CODE");
    abort();
#endif
}

void match_bloom_filter(u32 sid, const u8* ibuf, size_t ilen, u8** obuf, size_t* olen)
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    auto output = handler->match_filter(global->session(sid).cipher().decrypt_str(ibuf, ilen));
    global->dump_enc(sid, output, obuf, olen);
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

void aggregate(u32 sid, const u8* ibuf, size_t ilen)
{
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    handler->build_result(global->session(sid).cipher().decrypt(ibuf, ilen));
#else
    (void)(sid);
    (void)(ibuf);
    (void)(ilen);

    TRACE_ENCLAVE("UNREACHABLE CODE");
    abort();
#endif
}

void get_result(u32 sid, u8** obuf, size_t* olen)
{
    global->dump_enc(sid, handler->get_result(), obuf, olen);
}
