#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "spdlog.hpp"

#include "../host/socket/socket.h"

struct Message
{
    uint32_t session_id = -1;
    uint32_t message_type = -1;
    uint32_t payload_len = -1;
    std::uint8_t* payload = nullptr;

    Message() = default;

    explicit Message(uint32_t payload_len) : payload_len(payload_len)
    {
        payload = u8p(calloc(payload_len, 1));
    }

    Message(uint32_t session_id, uint32_t message_type, uint32_t payload_len)
        : session_id(session_id), message_type(message_type), payload_len(payload_len)
    {
        payload = u8p(calloc(payload_len, 1));
    }

    ~Message()
    {
        if (payload != nullptr)
        {
            free(payload);
        }
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

        return msg;
    }

    void send(const Message& msg)
    {
        connection->send(u8p(&msg), sizeof(uint32_t) * 3, true);
        connection->send(msg.payload, msg.payload_len);
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
