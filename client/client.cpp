
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <tuple>

#define __OUTSIDE_ENCLAVE__

#include "common/uint128.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/sha256.hpp"
#include "message_types.hpp"
#include "paillier.hpp"
#include "sgx/attestation.hpp"
#include "timer.hpp"
#include "utils/spdlog.hpp"
#include "utils/zmq.hpp"

using nlohmann::json;
using std::string;
using zmq::context_t;

std::shared_ptr<mbedtls::ctr_drbg> rand_ctx;
std::map<uint32_t, std::shared_ptr<PSI::Session>> sessions;
Timer timer;

/*
 * output:  vid, this_pk, format_setting
 */
auto verifier_generate_challenge(VerifierContext& ctx, int vid) -> v8
{
    /* set verifier id; generate and dump ephemeral public key */
    ctx.vid = vid;

    /* generate output object */
    json request = json::object({{"vid", ctx.vid}, {"vpk", ctx.vpk}, {"format_settings", ctx.core.format_settings()}});

    return json::to_msgpack(request);
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

    /* set vpk in ecdh context */
    ctx.ecdh.read_public(ctx.apk);

    /* build crypto context */
    auto [sid, session] = ctx.complete_attestation();

    if (sessions.find(sid) != sessions.end())
    {
        TRACE_ENCLAVE("session id collision: vid=%04x aid=%04x sid=%08x", ctx.vid, ctx.aid, sid);
        abort();
    }
    else
    {
        sessions.insert({sid, session});
    }

    return sid;
}

auto client(const string& server_addr, context_t* io, int id, const v8& pk) -> std::tuple<v8, size_t, size_t>
{
    /* construct a request socket and connect to interface */
    auto client = Socket::connect(*io, server_addr.c_str());
    VerifierContext vctx(rand_ctx);
    uint32_t sid;

    /* attestation */
    timer(fmt::format("c/s{}: initiate attestation", id));

    {
        json request = {{"sid", -1}, {"type", AttestationRequest}, {"payload", verifier_generate_challenge(vctx, id)}};
        assert(request["type"].get<MessageType>() == AttestationRequest);
        client.send(request);

        json response = client.recv();
        assert(response["type"].get<MessageType>() == AttestationResponse);
        auto payload = response["payload"].get<v8>();
        sid = verifier_process_response(vctx, payload);
        assert(sid == response["sid"].get<uint32_t>());
    }

    timer(fmt::format("c/s{}: initiate query", id));

    auto session = sessions[sid];
    SPDLOG_DEBUG("client session to s{}: sid={:08x}", id, sid);

    /* set public key */
    json request = {{"sid", sid}, {"type", QueryRequest}, {"payload", session->cipher().encrypt(pk, *rand_ctx)}};
    assert(request["type"].get<MessageType>() == QueryRequest);
    client.send(request);

    /* get match result and aggregate */
    json response = client.recv();
    assert(response["type"].get<MessageType>() == QueryResponse);
    assert(sid == response["sid"].get<uint32_t>());
    auto result = session->cipher().decrypt(response["payload"].get<v8>());

    timer(fmt::format("c/s{}: result received", id));

    auto [bytes_sent, bytes_received] = client.statistics();

    client.close();

    return std::make_tuple(result, bytes_sent, bytes_received);
}

void output_result(PSI::Paillier& homo_crypto, const json& obj)
{
#if PSI_VERBOSE

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_JOIN_COUNT

    (void)(homo_crypto);

    auto count = obj[0].get<size_t>();
    SPDLOG_INFO("{}", count);

#else

    for (auto pair : obj)
    {
        a8<sizeof(uint128_t)> key_bin = pair[0];

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
        (void)(homo_crypto);
        auto val = pair[1].get<uint64_t>();
#else
        v8 val_bin = pair[1];
        auto val = homo_crypto.decrypt(mbedtls::mpi(val_bin.data(), val_bin.size())).to_unsigned<uint64_t>();
#endif

        SPDLOG_INFO("{:sn} {:016x}", spdlog::to_hex(key_bin), val);
    }

#endif

#else

    (void)(homo_crypto);
    (void)(obj);

#endif
}

auto main(int argc, const char* argv[]) -> int
{
    /* pasrse command line argument */

    CLI::App app;

    string s0_endpoint;
    app.add_option("--s0-endpoint", s0_endpoint, "server 0's endpoint")->required();

    string s1_endpoint;
    app.add_option("--s1-endpoint", s1_endpoint, "server 1's endpoint")->required();

    string test_id = fmt::format("{:%Y%m%dT%H%M%S}", fmt::localtime(time(nullptr)));
    app.add_option("--test-id", test_id, "test identifier");

    CLI11_PARSE(app, argc, argv);

    /* configure logger */

    spdlog::set_level(spdlog::level::trace);
    spdlog::set_pattern("%^[%Y-%m-%d %H:%M:%S.%e] [%L] [c] [%t] %s:%# -%$ %v");

    const std::array<string, 2> endpoint = {s0_endpoint, s1_endpoint};
    SPDLOG_INFO("server endpoint: {} {}", endpoint[0], endpoint[1]);

    /* prepare public key */

    rand_ctx = std::make_shared<mbedtls::ctr_drbg>();

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(PSI_PAILLIER_PK_LEN, *rand_ctx);
    auto pubkey = homo_crypto.dump_pubkey();

    /* initialize the zmq context with a single IO thread */
    context_t context{1};

    timer("start");

    /* start client */
    auto c0 = std::async(std::launch::async, client, endpoint[0], &context, 0, pubkey);
    auto c1 = std::async(std::launch::async, client, endpoint[1], &context, 1, pubkey);

    /* wait for the result */
    auto [v0, c0_sent, c0_recv] = c0.get();
    auto [v1, c1_sent, c1_recv] = c1.get();

    timer("done");

    /* print out query result */
    output_result(homo_crypto, json::from_msgpack(v0));
    output_result(homo_crypto, json::from_msgpack(v1));

    /* dump statistics*/
    json output = json::object(
        {{"PSI_PAILLIER_PK_LEN", PSI_PAILLIER_PK_LEN},
         {"PSI_MELBOURNE_P", PSI_MELBOURNE_P},
         {"PSI_SELECT_POLICY", PSI_SELECT_POLICY},
         {"PSI_AGGREGATE_POLICY", PSI_AGGREGATE_POLICY},
         {"c/s0:sent", c0_sent},
         {"c/s0:recv", c0_recv},
         {"c/s1:sent", c1_sent},
         {"c/s1:recv", c1_recv},
         {"time", timer.to_json()}});

    {
        auto fn = fmt::format("{}-client.json", test_id);

        FILE* fp = std::fopen(fn.c_str(), "w");
        fputs(output.dump().c_str(), fp);
        fclose(fp);

        SPDLOG_INFO("Benchmark written to {}", fn);
    }

    return 0;
}
