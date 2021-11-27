#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

#include "common/types.hpp"
#include "config.hpp"
#include "enclave.hpp"
#include "host/message.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "prng.hpp"
#include "type/message.hpp"

constexpr size_t TEST_SIZE = (1 << 20);

class PSIContext
{
    PSIEnclave enclave;
    v32 data_keys;
    v32 data_vals;

    uint32_t csid;
    uint32_t isid;
    uint32_t osid;

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    struct
    {
        std::mutex client;
        std::mutex active;
        std::mutex passive;
    } lock;
#endif

    int half;

  public:
    explicit PSIContext(const char* enclave_image_path, size_t data_size, size_t max_key, int half)
        : enclave(enclave_image_path, false), half(half)
    {
        /* generate random dataset */
        PRNG<uint32_t> prng;

        for (size_t i = 0; i < data_size; i++)
        {
            data_keys.push_back(prng() % max_key);
            data_vals.push_back(prng());
        }
#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
        /* initialize locks */
        lock.active.lock();
        lock.passive.lock();
        lock.client.lock();
#endif
    }

    auto get_timer() -> Timer&
    {
        return enclave.get_timer();
    }

    /*
     * member accessor
     */

    void set_client_sid(uint32_t sid)
    {
        csid = sid;
    }

    void set_peer_isid(uint32_t sid)
    {
        isid = sid;
    }

    void set_peer_osid(uint32_t sid)
    {
        osid = sid;
    }

    /*
     * attestation routines
     */

    auto prepare_attestation_req() -> MessagePtr
    {
        buffer request;
        enclave.verifier_generate_challenge(request);
        return std::make_shared<Message>(-1, AttestationRequest, request.size, request.data);
    }

    auto handle_attestation_req(const v8& request) -> MessagePtr
    {
        buffer response;
        uint32_t sid = enclave.attester_generate_response(request, response);
        return std::make_shared<Message>(sid, AttestationResponse, response.size, response.data);
    }

    auto process_attestation_resp(const v8& response) -> uint32_t
    {
        auto sid = enclave.verifier_process_response(response);
        return sid;
    }

    /*
     * client routines
     */

    auto handle_query_request(uint32_t sid, const v8& payload) -> MessagePtr
    {
        assert(sid == csid);
        enclave.set_client_query(sid, payload, half, data_keys, data_vals);

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
        /* client sid and public key are set, ready for peer to use */
        SPDLOG_DEBUG("Unlocking lock.active");
        lock.active.unlock();
        SPDLOG_DEBUG("Unlocking lock.passive");
        lock.passive.unlock();

        /* waiting for peer to build the result */
        SPDLOG_DEBUG("Locking lock.client");
        lock.client.lock();
#endif

        buffer output;
        enclave.get_result(csid, output);

        /* build and return query result */
        return std::make_shared<Message>(sid, QueryResponse, output.size, output.data);
    }

    /*
     * peer routines
     */

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    /*
     * active
     */
    auto prepare_compute_req() -> MessagePtr
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking lock.active");
        lock.active.lock();

        buffer request;
        enclave.build_bloom_filter(osid, request);

        return std::make_shared<Message>(osid, ComputeRequest, request.size, request.data);
    }

    void process_compute_resp(uint32_t sid, const v8& payload)
    {
        assert(sid == osid);

        enclave.aggregate(sid, payload);

        /*
         * result prepared, ready for client to take
         */
        SPDLOG_DEBUG("Unlocking lock.client");
        lock.active.unlock();
        SPDLOG_DEBUG("Unlocking lock.client");
        lock.client.unlock();
    }

    /*
     * passive
     */
    auto handle_compute_req(uint32_t sid, const v8& payload) -> MessagePtr
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking lock.passive");
        lock.passive.lock();

        assert(sid == isid);

        buffer response;
        enclave.match_bloom_filter(sid, payload, response);

        SPDLOG_DEBUG("Unlocking lock.passive");
        lock.passive.unlock();

        return std::make_shared<Message>(sid, ComputeResponse, response.size, response.data);
    }
#endif
};
