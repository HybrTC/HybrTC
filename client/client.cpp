#include <cstdint>
#include <iostream>
#include <string>

#include <openenclave/host.h>
#include <nlohmann/json.hpp>
#include <spdlog.hpp>
#include <zmq.hpp>

#include "common/uint128.hpp"
#include "crypto/ctr_drbg.hpp"
#include "paillier.hpp"

auto main(int argc, const char* argv[]) -> int
{
    auto log = spdlog::stdout_color_mt("console");
    log->set_level(spdlog::level::debug);

    OE_UNUSED(argc);
    OE_UNUSED(argv);

    mbedtls::ctr_drbg ctr_drbg;

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(512, ctr_drbg);
    auto pubkey = homo_crypto.dump_pubkey();

    // initialize the zmq context with a single IO thread
    zmq::context_t context{1};

    // construct a REQ (request) socket and connect to interface
    zmq::socket_t socket{context, zmq::socket_type::req};
    socket.connect("tcp://localhost:5555");

    log->debug("public key: {}", spdlog::to_hex(pubkey));
    socket.send(zmq::buffer(pubkey), zmq::send_flags::none);

    // wait for reply from server
    zmq::message_t reply{};
    (void)socket.recv(reply, zmq::recv_flags::none);

    // handle reply
    const auto* data = reinterpret_cast<const uint8_t*>(reply.data());
    auto result_arr = nlohmann::json::from_msgpack(data, data + reply.size());

    for (auto pair : result_arr)
    {
        std::array<uint8_t, sizeof(uint128_t)> key_bin = pair[0];
        std::vector<uint8_t> val_bin = pair[1];
        auto dec =
            homo_crypto.decrypt(mbedtls::mpi(val_bin.data(), val_bin.size()))
                .to_unsigned<uint64_t>();

        log->info("{:sn} {:016x}", spdlog::to_hex(key_bin), dec);
    }

    return 0;
}