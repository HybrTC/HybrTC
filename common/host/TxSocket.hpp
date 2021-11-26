#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "common/types.hpp"
#include "message.hpp"
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
        socket.connection = std::make_shared<SocketConnection>(socket.server->accept());
        return socket;
    }

    static auto connect(const char* host, uint16_t port) -> TxSocket
    {
        TxSocket socket;
        socket.connection = std::make_shared<SocketConnection>(host, port);
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

        SPDLOG_DEBUG(
            "TxSocket received sid={:08x} type={} len={}", msg->session_id, msg->message_type, msg->payload_len);

        return msg;
    }

    void send(const Message& msg)
    {
        connection->send(u8p(&msg), sizeof(uint32_t) * 3, true);
        connection->send(msg.payload, msg.payload_len);

        SPDLOG_DEBUG("TxSocket sent sid={:08x} type={} len={}", msg.session_id, msg.message_type, msg.payload_len);
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
