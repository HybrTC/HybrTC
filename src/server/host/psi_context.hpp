#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

#include "common/message.hpp"
#include "common/types.hpp"
#include "config.hpp"
#include "enclave.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "prng.hpp"

constexpr size_t TEST_SIZE = (1 << 20);

class PSIContext
{
    PSIEnclave enclave;
    v32 data_keys;
    v32 data_vals;

    uint32_t csid;
    uint32_t prev_sid;
    uint32_t next_sid;

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
    struct
    {
        std::mutex client;
        std::mutex active;
        std::mutex passive;
    } lock;
#endif

    unsigned id = -1;
    unsigned count = -1;

  public:
    explicit PSIContext(
        const char* enclave_image_path,
        size_t data_size,
        size_t max_key,
        unsigned server_id,
        unsigned server_cnt)
        : enclave(enclave_image_path, false, server_id, server_cnt), id(server_id), count(server_cnt)
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

    [[nodiscard]] auto server_count() const -> unsigned
    {
        return count;
    }

    [[nodiscard]] auto server_id() const -> unsigned
    {
        return id;
    }

    void set_client_sid(uint32_t sid)
    {
        csid = sid;
    }

    void set_previous_peer_sid(uint32_t sid)
    {
        prev_sid = sid;
    }

    void set_next_peer_sid(uint32_t sid)
    {
        next_sid = sid;
    }

    /*
     * attestation routines
     */

    auto prepare_attestation_req() -> MessagePtr
    {
        buffer request;
        enclave.verifier_generate_challenge(request);
        return std::make_shared<Message>(-1, Message::AttestationRequest, request.size, request.data);
    }

    auto handle_attestation_req(const v8& request) -> MessagePtr
    {
        buffer response;
        uint32_t sid = enclave.attester_generate_response(request, response);
        return std::make_shared<Message>(sid, Message::AttestationResponse, response.size, response.data);
    }

    auto process_attestation_resp(uint8_t* data, size_t size) -> uint32_t
    {
        auto sid = enclave.verifier_process_response({data, size});
        return sid;
    }

    /*
     * client routines
     */

    auto handle_query_request(uint32_t sid, const v8& payload) -> MessagePtr
    {
        assert(sid == csid);
        enclave.set_client_query(payload, data_keys, data_vals);

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
        enclave.get_result(output);

        /* build and return query result */
        return std::make_shared<Message>(sid, Message::QueryResponse, output.size, output.data);
    }

    /*
     * peer routines
     */

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT

    auto prepare_compute_req() -> MessagePtr
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking lock.active");
        lock.active.lock();

        buffer request;
        enclave.gen_compute_request(request);

        lock.active.unlock();
        SPDLOG_DEBUG("Unlocked lock.active");

        return std::make_shared<Message>(next_sid, Message::ComputeRequest, request.size, request.data);
    }

    auto handle_compute_req(const uint8_t* data, size_t size) -> MessagePtr
    {
        /* wait for client public key to be set */
        SPDLOG_DEBUG("Locking lock.passive");
        lock.passive.lock();

        buffer output;
        int otype = enclave.pro_compute_request({const_cast<uint8_t*>(data), size}, output);

        lock.passive.unlock();
        SPDLOG_DEBUG("Unlocked lock.passive");

        if (otype == Message::ComputeRequest)
        {
            return std::make_shared<Message>(next_sid, Message::ComputeRequest, output.size, output.data);
        }
        if (otype == Message::ComputeResponse)
        {
            return std::make_shared<Message>(prev_sid, Message::ComputeResponse, output.size, output.data);
        }
        return nullptr;
    }

    auto process_compute_resp(const uint8_t* data, size_t size) -> MessagePtr
    {
        SPDLOG_DEBUG("Locking lock.active");
        lock.active.lock();

        buffer output;
        enclave.pro_compute_response({const_cast<uint8_t*>(data), size}, output);

        lock.active.unlock();
        SPDLOG_DEBUG("Unlocked lock.active");

        if (output.data == nullptr)
        {
            /*
             * result prepared, ready for client to take
             */

            lock.client.unlock();
            SPDLOG_DEBUG("Unlocked lock.client");
            return nullptr;
        }

        /* pass the response to the previous peer */
        return std::make_shared<Message>(prev_sid, Message::ComputeResponse, output.size, output.data);
    }

#endif
};
