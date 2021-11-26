#pragma once

#include <cstddef>
#include <memory>
#include <mutex>

#include "crypto/ctr_drbg.hpp"
#include "sgx/attestation.hpp"

class EnclaveContext
{
    std::vector<sptr<VerifierContext>> verifiers;
    std::map<u32, sptr<PSI::Session>> sessions;
    sptr<mbedtls::ctr_drbg> rand_ctx;

    std::mutex session_lock;

    void new_session(u32 sid, sptr<PSI::Session> session, const AttestationContext& ctx);

  public:
    EnclaveContext();

    static void dump(const std::string& bytes, uint8_t** obuf, size_t* olen);
    static void dump(const v8& bytes, uint8_t** obuf, size_t* olen);

    void dump_enc(u32 sid, const std::string& bytes, uint8_t** obuf, size_t* olen);
    void dump_enc(u32 sid, const v8& bytes, uint8_t** obuf, size_t* olen);

    auto rand_ptr() -> sptr<mbedtls::ctr_drbg>;

    auto rand() -> mbedtls::ctr_drbg&;

    auto session(u32 session_id) -> PSI::Session&;

    /*
     * output:  vid, this_pk, format_setting
     */
    void verifier_generate_challenge(u8** obuf, size_t* olen);

    /*
     * input:   vid, peer_pk, format_settings
     * output:  vid, aid, this_pk, evidence
     * return:  session_id
     */
    auto attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32;

    /*
     * input:   vid, aid, evidence
     * output:  attestation_result
     * return:  session_id if success else -1
     */
    auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32;
};
