#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <openenclave/host.h>
#include <nlohmann/json.hpp>
#include <spdlog.hpp>
#include <zmq.hpp>

#include "common/types.hpp"
#include "common/uint128.hpp"
#include "enclave.hpp"
#include "paillier.hpp"
#include "prng.hpp"
#include "prp.hpp"

#define LOGGER "consolse"

template <class KT, class VT>
auto random_dataset(size_t size) -> std::pair<std::vector<KT>, std::vector<VT>>
{
    PRNG<uint32_t> prng;

    std::pair<std::vector<KT>, std::vector<VT>> dataset;

    for (size_t i = 0; i < size; i++)
    {
        dataset.first.push_back(prng());
        dataset.second.push_back(prng());
    }

    return dataset;
}

void hexdump(const char* name, const buffer& buf)
{
    auto log = spdlog::get(LOGGER);
    log->debug("{}: {}", name, spdlog::to_hex(buf.data, buf.data + buf.size));
}

auto psi(const char* image_path, const v8& pubkey) -> v8
{
    auto log = spdlog::get(LOGGER);

    SPIEnclave enclave_a(image_path, false);
    SPIEnclave enclave_b(image_path, false);

    buffer pk_a;
    buffer format_setting_a;
    enclave_a.initialize_attestation(pk_a, format_setting_a);
    hexdump("pk_a", pk_a);

    buffer pk_b;
    buffer format_setting_b;
    enclave_b.initialize_attestation(pk_b, format_setting_b);
    hexdump("pk_b", pk_b);

    buffer evidence_a;
    enclave_a.generate_evidence(pk_b, format_setting_b, evidence_a);

    buffer evidence_b;
    enclave_b.generate_evidence(pk_a, format_setting_a, evidence_b);

    bool result_a = enclave_a.finish_attestation(evidence_b);
    bool result_b = enclave_b.finish_attestation(evidence_a);

    if (result_a && result_b)
    {
        log->info("attestation succeed");
    }
    else
    {
        log->warn("attestation failed");
        exit(EXIT_FAILURE);
    }

    constexpr size_t TEST_SIZE = (1 << 20);
    auto ds1 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);
    auto ds2 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);

    buffer bloom_filter_a;
    enclave_a.build_bloom_filter(ds1.first, bloom_filter_a);

    log->debug(
        "enclave_a.build_bloom_filter(ds1.first) => filter_size = {:x}",
        bloom_filter_a.size);

    buffer msg;
    enclave_b.match_bloom_filter(
        ds2.first, ds2.second, bloom_filter_a, pubkey, msg);

    buffer result1;
    enclave_a.aggregate(ds1.first, ds1.second, msg, pubkey, result1);

    return v8(result1.data, result1.data + result1.size);
}

auto main(int argc, const char* argv[]) -> int
{
    auto log = spdlog::stdout_color_mt(LOGGER);
    log->set_level(spdlog::level::debug);

    if (argc != 3)
    {
        fprintf(
            stderr,
            "Usage: %s  <enclave_id:0/1> <enclave_image_path>\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    const int server_id = std::stoi(argv[1], nullptr, 0);
    const char* enclave_image_path = argv[2];

    // initialize the zmq context with a single IO thread
    zmq::context_t context{1};

    // construct a REP (reply) socket and bind to interface
    zmq::socket_t socket{context, zmq::socket_type::rep};
    socket.bind("tcp://*:5555");

    // receive a request from client
    zmq::message_t request;
    (void)socket.recv(request, zmq::recv_flags::none);

    const auto* pubkey = u8p(request.data());
    auto ret = psi(enclave_image_path, v8(pubkey, pubkey + request.size()));

    // send the reply to the client
    socket.send(zmq::buffer(ret), zmq::send_flags::none);

    return 0;
}