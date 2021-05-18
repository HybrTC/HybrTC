#include "common/types.hpp"
#include "config.hpp"
#include "enclave_context.hpp"
#include "psi/join_handler.hpp"
#include "psi/select_handler.hpp"

#include "helloworld_t.h"

sptr<EnclaveContext> global;

static void init()
{
    if (global == nullptr)
    {
        global = std::make_shared<EnclaveContext>();
    }
}

void verifier_generate_challenge(u8** obuf, size_t* olen)
{
    init();
    global->verifier_generate_challenge(obuf, olen);
}

auto attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    init();
    return global->attester_generate_response(ibuf, ilen, obuf, olen);
}

auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    return global->verifier_process_response(ibuf, ilen);
}

#ifdef PSI_SELECT_ONLY
sptr<SelectHandler> handler;
#else
sptr<JoinHandler> handler;
#endif

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
    handler->set_public_key(global->session(sid).decrypt(ibuf, ilen));
#ifndef PSI_SELECT_ONLY
    handler->set_half(half);
#endif

    handler->load_data(data_key, data_val, data_size);
}

void get_select_result(u32 sid, u8** obuf, size_t* olen)
{
#ifdef PSI_SELECT_ONLY
    global->dump_enc(sid, handler->get_result(), obuf, olen);
#else
    (void)(sid);
    (void)(obuf);
    (void)(olen);

    abort();
#endif
}

void build_bloom_filter(u32 sid, u8** obuf, size_t* olen)
{
    global->dump_enc(sid, handler->build_filter(), obuf, olen);
}

void match_bloom_filter(u32 sid, const u8* ibuf, size_t ilen, u8** obuf, size_t* olen)
{
    global->dump_enc(sid, handler->match_filter(global->session(sid).decrypt(ibuf, ilen)), obuf, olen);
}

void aggregate(u32 peer_sid, u32 client_sid, const u8* ibuf, size_t ilen, u8** obuf, size_t* olen)
{
    global->dump_enc(client_sid, handler->aggregate(global->session(peer_sid).decrypt(ibuf, ilen)), obuf, olen);
}
