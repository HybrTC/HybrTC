#pragma once

#include <cstdint>
#include <memory>

#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "spdlog.hpp"

#include "../host/socket/socket.h"

struct Message
{
    uint32_t session_id;
    uint32_t message_type;
    uint32_t payload_len;
    uint8_t payload[]; // NOLINT(modernize-avoid-c-arrays)

    Message() = delete;
    static auto create(uint32_t session_id, uint32_t message_type, uint32_t payload_len) -> std::shared_ptr<Message>
    {
        void* buf = calloc(sizeof(Message) + payload_len, 1);

        Message& msg = *reinterpret_cast<Message*>(buf);
        msg.session_id = session_id;
        msg.message_type = message_type;
        msg.payload_len = payload_len;

        return std::shared_ptr<Message>(&msg, free);
    }
};

using MessagePtr = std::shared_ptr<Message>;

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
        size_t len;

        struct
        {
            uint32_t session_id;
            uint32_t message_type;
            uint32_t payload_len;
        } hdr;
        len = connection->recv(&hdr, sizeof(hdr));
        if (len == 0)
        {
            return nullptr;
        }

        auto msg = Message::create(hdr.session_id, hdr.message_type, hdr.payload_len);

        len = connection->recv(msg->payload, msg->payload_len);
        if (len == 0)
        {
            fprintf(stderr, "unexpected missing message body\n");
            exit(EXIT_FAILURE);
        }

        return msg;
    }

    void send(const Message& msg)
    {
        connection->send(u8p(&msg), sizeof(Message) + msg.payload_len);
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
