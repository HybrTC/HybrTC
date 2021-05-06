#include <cstdint>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <thread>

#include <openenclave/host.h>
#include <nlohmann/json.hpp>
#include <spdlog.hpp>
#include <zmq.hpp>

#define __OUTSIDE_ENCLAVE__

#include "attestation.hpp"
#include "common/uint128.hpp"
#include "crypto/ctr_drbg.hpp"
#include "message_types.hpp"
#include "paillier.hpp"
#include "zmq_utils.hpp"

using nlohmann::json;

std::shared_ptr<mbedtls::ctr_drbg> ctr_drbg;
std::map<uint32_t, std::shared_ptr<mbedtls::aes_gcm_256>> sessions;

/*
 * output:  vid, this_pk, format_setting
 */
auto verifier_generate_challenge(VerifierContext& ctx, int vid) -> v8
{
    /* set verifier id; generate and dump ephemeral public key */
    ctx.vid = vid;
    ctx.vpk = ctx.ecdh.make_public(*ctr_drbg);

    /* generate output object */
    json json = json::object(
        {{"vid", ctx.vid},
         {"vpk", ctx.vpk},
         {"format_settings", ctx.core.format_settings()}});

    return json::to_msgpack(json);
}

/*
 * input:   vid, aid, evidence
 * output:  attestation_result
 */
auto verifier_process_response(VerifierContext& ctx, const v8& ibuf) -> uint32_t
{
    /* deserialize and handle input */
    auto input = json::from_msgpack(ibuf);

    ctx.aid = input["aid"].get<uint16_t>();      // set attester id
    ctx.apk = input["apk"].get<v8>();            // set attester pubkey
    auto evidence = input["evidence"].get<v8>(); // load attestation evidence

    /* verify evidence */
    auto claims = ctx.core.verify_evidence(evidence).custom_claims_buffer();

    /* compare claims: (1) size (2) compare content in constant time */
    auto claims_ = ctx.build_claims();
    if (claims_.size() != claims.value_size)
    {
        return -1;
    }

    unsigned result = 0;
    for (size_t i = 0; i < claims_.size() && i < claims.value_size; i++)
    {
        result += (claims_[i] ^ claims.value[i]);
    }
    if (result != 0)
    {
        return -1;
    }

    /* build crypto context and free verifier context */
    return ctx.complete_attestation();
}

auto client(const char* server_addr, zmq::context_t* io, int id, const v8& pk)
    -> json
{
    // construct a request socket and connect to interface
    zmq::socket_t client = connect(*io, server_addr);
    VerifierContext vctx;
    uint32_t sid;

    /* attestation */
    {
        json request = {
            {"sid", -1},
            {"type", AttestationRequest},
            {"payload", verifier_generate_challenge(vctx, id)}};
        assert(request["type"].get<MessageType>() == AttestationRequest);
        send(client, request);

        json response = recv(client);
        assert(request["type"].get<MessageType>() == AttestationResponse);
        auto payload = request["payload"].get<v8>();
        sid = verifier_process_response(vctx, payload);
        assert(sid == request["sid"].get<uint32_t>());
    }

    auto crypto = sessions[sid];

    /* set public key */
    json request = {
        {"sid", -1},
        {"type", QueryRequest},
        {"payload", crypto->encrypt(pk, *ctr_drbg)}};
    assert(request["type"].get<MessageType>() == QueryRequest);
    send(client, request);

    /* get match result and aggregate */
    json response = recv(client);
    assert(request["type"].get<MessageType>() == QueryResponse);
    assert(sid == request["sid"].get<uint32_t>());
    auto result = crypto->decrypt(request["payload"].get<v8>());

    return json::from_msgpack(result);
}

auto main(int argc, const char* argv[]) -> int
{
    auto log = spdlog::stdout_color_mt("client");
    log->set_level(spdlog::level::debug);

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <endpoint1> <endpoint2>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const std::array<const char*, 2> endpoint = {argv[1], argv[2]};
    log->info("server endpoint: {} {}", endpoint[0], endpoint[1]);

    /* prepare public key */
    ctr_drbg = std::make_shared<mbedtls::ctr_drbg>();

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(512, *ctr_drbg);
    auto pubkey = homo_crypto.dump_pubkey();

    // initialize the zmq context with a single IO thread
    zmq::context_t context{1};

    // construct a REQ (request) socket and connect to interface
    zmq::socket_t socket{context, zmq::socket_type::req};
    socket.connect("tcp://localhost:5555");

    /* start client */
    auto c0 = std::async(
        std::launch::async, client, endpoint[0], &context, 0, pubkey);
    auto c1 = std::async(
        std::launch::async, client, endpoint[1], &context, 1, pubkey);

    auto p0 = c0.get();
    auto p1 = c1.get();

    auto log0 = spdlog::stdout_color_mt("c0");
    auto log1 = spdlog::stdout_color_mt("c1");

    for (auto pair : p0)
    {
        std::array<uint8_t, sizeof(uint128_t)> key_bin = pair[0];
        std::vector<uint8_t> val_bin = pair[1];
        auto dec =
            homo_crypto.decrypt(mbedtls::mpi(val_bin.data(), val_bin.size()))
                .to_unsigned<uint64_t>();

        log0->info("{:sn} {:016x}", spdlog::to_hex(key_bin), dec);
    }

    for (auto pair : p1)
    {
        std::array<uint8_t, sizeof(uint128_t)> key_bin = pair[0];
        std::vector<uint8_t> val_bin = pair[1];
        auto dec =
            homo_crypto.decrypt(mbedtls::mpi(val_bin.data(), val_bin.size()))
                .to_unsigned<uint64_t>();

        log1->info("{:sn} {:016x}", spdlog::to_hex(key_bin), dec);
    }

    return 0;
}