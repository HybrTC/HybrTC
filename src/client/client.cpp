#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <tuple>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#define __OUTSIDE_ENCLAVE__

#include "common/types.hpp"
#include "common/uint128.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/sha256.hpp"
#include "host/TxSocket.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "msg.pb.h"
#include "paillier.hpp"
#include "sgx/attestation.hpp"

using nlohmann::json;
using std::string;

std::shared_ptr<mbedtls::ctr_drbg> rand_ctx;
std::map<uint32_t, std::shared_ptr<PSI::Session>> sessions;
Timer timer;

/*
 * output:  vid, this_pk, format_setting
 */
auto verifier_generate_challenge(VerifierContext& ctx, int vid) -> std::shared_ptr<hybrtc::AttestationChallenge>
{
    /* set verifier id; generate and dump ephemeral public key */
    ctx.vid = vid;

    /* generate output object */
    auto challenge = std::make_shared<hybrtc::AttestationChallenge>();
    challenge->set_verifier_id(ctx.vid);
    challenge->set_verifier_pk(ctx.vpk);
    challenge->set_format_settings(ctx.core.format_settings());

    return challenge;
}

/*
 * input:   vid, aid, evidence
 * output:  attestation_result
 */
auto verifier_process_response(VerifierContext& ctx, const hybrtc::AttestationResponse& input) -> uint32_t
{
    /* handle input */

    ctx.aid = input.attester_id(); // set attester id
    ctx.apk = input.attester_pk(); // set attester pubkey
#if 0
// Should verify the evidence here. But our platform is outdated
const auto& evidence = input.evidence(); // load attestation evidence
#endif

    /* set vpk in ecdh context */
    ctx.ecdh.read_public(u8p(ctx.apk.data()), ctx.apk.size());

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

auto client(const std::string& host, uint16_t port, int id, const v8& pk) -> std::tuple<v8, size_t, size_t>
{
    SPDLOG_INFO("starting {} to {}:{}", __FUNCTION__, host, port);

    /* construct a request socket and connect to interface */
    auto client = TxSocket::connect(host.c_str(), port);

    VerifierContext vctx(rand_ctx);
    uint32_t sid;

    /* attestation */
    timer(fmt::format("c/s{}: initiate attestation", id));

    {
        {
            auto payload = verifier_generate_challenge(vctx, id);
            client.send(-1, Message::AttestationRequest, payload->SerializeAsString());
        }

        auto response = client.recv();
        if (response->message_type != Message::AttestationResponse)
        {
            abort();
        }

        hybrtc::AttestationResponse payload;
        payload.ParseFromArray(response->payload, static_cast<int>(response->payload_len));
        sid = verifier_process_response(vctx, payload);
        assert(sid == response["sid"].get<uint32_t>());
    }

    timer(fmt::format("c/s{}: initiate query", id));

    auto session = sessions[sid];
    SPDLOG_DEBUG("client session to s{}: sid={:08x}", id, sid);

    /* set public key */
    {
        auto payload = session->cipher().encrypt(pk, *rand_ctx);
        client.send(sid, Message::QueryRequest, payload.size(), payload.data());
    }

    /* get match result and aggregate */
    auto response = client.recv();
    if (response == nullptr)
    {
        SPDLOG_ERROR("Cannot Receive QueryResponse");
        exit(EXIT_FAILURE);
    }
    if (response->message_type != Message::QueryResponse)
    {
        SPDLOG_ERROR("Unexpected message type {}", response->message_type);
        abort();
    }
    if (response->session_id != sid)
    {
        abort();
    }
    auto result = session->cipher().decrypt(response->payload, response->payload_len);

    timer(fmt::format("c/s{}: result received", id));

    auto [bytes_sent, bytes_received] = client.statistics();

    client.close();

    return std::make_tuple(result, bytes_sent, bytes_received);
}

void output_result(PSI::Paillier& homo_crypto, const v8& buf)
{
    hybrtc::Pairs pairs;
    pairs.ParseFromArray(buf.data(), static_cast<int>(buf.size()));

    if (PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_JOIN_COUNT)
    {
        (void)(homo_crypto);

        auto bin = pairs.pairs(0).key();
        size_t count = *reinterpret_cast<const size_t*>(bin.data());
        SPDLOG_INFO("{}", count);
    }
    else
    {
        for (const auto& pair : pairs.pairs())
        {
            const auto& key_bin = pair.key();
            const auto& val_bin = pair.value();

            uint64_t val;
            if (PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT)
            {
                val = *reinterpret_cast<const uint32_t*>(val_bin.data());
            }
            else
            {
                val = homo_crypto.decrypt(mbedtls::mpi(u8p(val_bin.data()), val_bin.size())).to_unsigned<uint64_t>();
            }
            SPDLOG_INFO("{:sn} {:016x}", spdlog::to_hex(key_bin), val);
        }
    }
}

auto main(int argc, const char* argv[]) -> int
{
    /* pasrse command line argument */

    CLI::App app;

    string topo;
    app.add_option("--topo", topo, "network topology")->required();

    string test_id = fmt::format("{:%Y%m%dT%H%M%S}", fmt::localtime(time(nullptr)));
    app.add_option("--test-id", test_id, "test identifier");

    CLI11_PARSE(app, argc, argv);

    /* parse network topology */
    auto servers = json::parse(topo);

    /* configure logger */

    spdlog::set_level(spdlog::level::trace);
    spdlog::set_pattern("%^[%Y-%m-%d %H:%M:%S.%e] [%L] [c] [%t] %s:%# -%$ %v");

    /* prepare public key */

    rand_ctx = std::make_shared<mbedtls::ctr_drbg>();

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(PSI_PAILLIER_PK_LEN, *rand_ctx);
    auto pubkey = homo_crypto.dump_pubkey();

    timer("start");

    /* start client */
    std::vector<std::future<std::tuple<v8, std::uint64_t, std::uint64_t>>> futures;
    futures.reserve(servers.size());
    for (size_t i = 0; i < servers.size(); i++)
    {
        const auto& host = servers[i]["host"].get<std::string>();
        const auto& port = servers[i]["port"].get<std::uint16_t>();
        futures.emplace_back(std::async(std::launch::async, client, host, port, i, pubkey));
    }

    /* wait for the result */
    std::vector<std::tuple<v8, std::uint64_t, std::uint64_t>> results;
    results.reserve(futures.size());
    for (auto& future : futures)
    {
        results.emplace_back(future.get());
    }

    timer("done");

    /* collect communication result and print out query results */
    json comm = json::object();
    for (size_t i = 0; i < results.size(); i++)
    {
        const auto& r = results[i];
#if PSI_VERBOSE
        output_result(homo_crypto, std::get<0>(r));
#endif
        comm[fmt::format("c/s{}", i)] = {{"sent", std::get<1>(r)}, {"recv", std::get<2>(r)}};
    }

    /* prepare statistics */
    json output = json::object(
        {{"PSI_PAILLIER_PK_LEN", PSI_PAILLIER_PK_LEN},
         {"PSI_MELBOURNE_P", PSI_MELBOURNE_P},
         {"PSI_SELECT_POLICY", PSI_SELECT_POLICY},
         {"PSI_AGGREGATE_POLICY", PSI_AGGREGATE_POLICY},
         {"comm", comm},
         {"time", timer.to_json()}});

    /* dump statistics */
    {
        auto fn = fmt::format("{}-client.json", test_id);

        FILE* fp = std::fopen(fn.c_str(), "w");
        fputs(output.dump().c_str(), fp);
        fclose(fp);

        SPDLOG_INFO("Benchmark written to {}", fn);
    }

    return 0;
}
