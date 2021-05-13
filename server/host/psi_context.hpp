#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>

#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "enclave.hpp"
#include "message_types.hpp"
#include "prng.hpp"
#include "utils/spdlog.hpp"

constexpr size_t TEST_SIZE = (1 << 20);

class PSIContext
{
    SPIEnclave enclave;
    v32 data_keys;
    v32 data_vals;

    v32 left_keys;
    v32 left_vals;

    struct
    {
        uint32_t sid;
        std::mutex lock_build;
        std::mutex lock_match;
    } client_ctx;

    struct
    {
        uint32_t isid;
        uint32_t osid;
        v8 result;
        std::mutex lock;
    } peer_ctx;

    bool half;

  public:
    explicit PSIContext(const char* enclave_image_path, bool half)
        : enclave(enclave_image_path, false), half(half)
    {
        PRNG<uint32_t> prng;

        if (half)
        {
            for (size_t i = 0; i < TEST_SIZE / 2; i++)
            {
                data_keys.push_back(prng());
                data_vals.push_back(prng());
            }

            for (size_t i = TEST_SIZE / 2; i < TEST_SIZE; i++)
            {
                left_keys.push_back(prng());
                left_vals.push_back(prng());
            }
        }
        else
        {
            for (size_t i = 0; i < TEST_SIZE; i++)
            {
                data_keys.push_back(prng());
                data_vals.push_back(prng());
            }
        }

        SPDLOG_DEBUG("Locking client_ctx.lock");
        client_ctx.lock_build.lock();
        client_ctx.lock_match.lock();

        SPDLOG_DEBUG("Locking peer_ctx.lock");
        peer_ctx.lock.lock();
    }

    /*
     * member accessor
     */

    void set_client_sid(uint32_t sid)
    {
        client_ctx.sid = sid;
    }

    void set_peer_isid(uint32_t sid)
    {
        peer_ctx.isid = sid;
    }

    void set_peer_osid(uint32_t sid)
    {
        peer_ctx.osid = sid;
    }

    /*
     * attestation routines
     */

    auto prepare_attestation_req() -> nlohmann::json
    {
        buffer request;
        enclave.verifier_generate_challenge(request);

        return {
            {"sid", -1},
            {"type", AttestationRequest},
            {"payload", v8(request.data, request.data + request.size)}};
    }

    auto handle_attestation_req(const v8& request) -> nlohmann::json
    {
        buffer response;
        uint32_t sid = enclave.attester_generate_response(request, response);

        return {
            {"sid", sid},
            {"type", AttestationResponse},
            {"payload", v8(response.data, response.data + response.size)}};
    }

    auto process_attestation_resp(uint32_t sid, const v8& response) -> uint32_t
    {
        (void)(sid);
        uint32_t sid_ = enclave.verifier_process_response(response);
        assert(sid == sid_);
        return sid_;
    }

    /*
     * client routines
     */

    auto handle_query_request(uint32_t sid, const v8& payload) -> nlohmann::json
    {
        assert(sid == client_ctx.sid);
        enclave.set_paillier_public_key(sid, payload);

        /* client sid and public key are set, ready for peer to use */
        SPDLOG_DEBUG("Unlocking client_ctx.lock");
        client_ctx.lock_build.unlock();
        client_ctx.lock_match.unlock();

        /* waiting for peer to return the result */
        SPDLOG_DEBUG("Locking peer_ctx.lock");
        peer_ctx.lock.lock();

        /* build and return query result */
        return {
            {"sid", sid},
            {"type", QueryResponse},
            {"payload", peer_ctx.result}};
    }

    /*
     * peer routines
     */

    auto prepare_compute_req() -> nlohmann::json
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking client_ctx.lock_build");
        client_ctx.lock_build.lock();
        buffer request;
        enclave.build_bloom_filter(peer_ctx.osid, data_keys, request);
        return {
            {"sid", peer_ctx.osid},
            {"type", ComputeRequest},
            {"payload", v8(request.data, request.data + request.size)}};
    }

    auto handle_compute_req(uint32_t sid, const v8& payload) -> nlohmann::json
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking client_ctx.lock_match");
        client_ctx.lock_match.lock();

        assert(sid == peer_ctx.isid);

        buffer response;
        if (half)
        {
            enclave.match_bloom_filter(
                sid, left_keys, left_vals, payload, response);
        }
        else
        {
            enclave.match_bloom_filter(
                sid, data_keys, data_vals, payload, response);
        }

        return {
            {"sid", sid},
            {"type", ComputeResponse},
            {"payload", v8(response.data, response.data + response.size)}};
    }

    void process_compute_resp(uint32_t sid, const v8& payload)
    {
        assert(sid == peer_ctx.osid);

        buffer output;
        enclave.aggregate(
            sid, client_ctx.sid, data_keys, data_vals, payload, output);
        peer_ctx.result = v8(output.data, output.data + output.size);

        /*
         * result prepared, ready for client to take
         */
        SPDLOG_DEBUG("Unlocking peer_ctx.lock");
        peer_ctx.lock.unlock();
    }
};
