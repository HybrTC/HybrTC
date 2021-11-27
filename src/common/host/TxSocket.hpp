#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "common/message.hpp"
#include "common/types.hpp"
#include "crypto/sha256.hpp"
#include "socket/socket.h"
#include "spdlog.hpp"

class TxSocket
{
    std::shared_ptr<SocketServer> server = nullptr;
    std::shared_ptr<SocketConnection> connection = nullptr;

  public:
    static auto listen(int port) -> TxSocket
    {
        TxSocket socket;
        socket.server = std::make_shared<SocketServer>(port);
        return socket;
    }

    auto accept() -> bool
    {
        connection = std::make_shared<SocketConnection>(server->accept());
        return connection != nullptr;
    }

    static auto connect(const char* host, uint16_t port) -> TxSocket
    {
        TxSocket socket;
        socket.connection = std::make_shared<SocketConnection>(host, port);
        SPDLOG_DEBUG("TxSocket connected to {}:{}", host, port);
        return socket;
    }

    auto recv() -> MessagePtr
    {
        MessagePtr msg = std::make_shared<Message>();

        if (connection->recv(msg.get(), sizeof(uint32_t) * 3) == 0)
        {
            return nullptr;
        }

        msg->payload = u8p(connection->recv(msg->payload_len));
        if (msg->payload == nullptr)
        {
            fprintf(stderr, "unexpected missing message body\n");
            exit(EXIT_FAILURE);
        }

#if PSI_VERBOSE
        mbedtls::sha256 h;
        h.update(msg->payload, msg->payload_len);
        auto d = h.finish();

        SPDLOG_DEBUG(
            "TxSocket received from {} sid={:08x} type={:#02x} payload_len={}: {}",
            connection->get_peer_address(),
            msg->session_id,
            msg->message_type,
            msg->payload_len,
            spdlog::to_hex(d));
#endif

        return msg;
    }

    void send(const Message& msg)
    {
        connection->send(u8p(&msg), sizeof(uint32_t) * 3, true);
        connection->send(msg.payload, msg.payload_len);

#if PSI_VERBOSE
        mbedtls::sha256 h;
        h.update(msg.payload, msg.payload_len);
        auto d = h.finish();

        SPDLOG_DEBUG(
            "TxSocket sent to {} sid={:08x} type={:#02x} payload_len={}: {}",
            connection->get_peer_address(),
            msg.session_id,
            msg.message_type,
            msg.payload_len,
            spdlog::to_hex(d));
#endif
    }

    void send(uint32_t session_id, uint32_t message_type, const std::string& payload)
    {
        send(session_id, message_type, payload.size(), payload.data());
    }

    void send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const void* payload)
    {
        for (uint32_t val : {session_id, message_type, payload_len})
        {
            connection->send(val, true);
        }
        connection->send(payload, payload_len);
    }

    auto statistics() -> std::pair<size_t, size_t>
    {
        return connection->statistics();
    }

    void close()
    {
        connection = nullptr;
        server = nullptr;
    }
};
