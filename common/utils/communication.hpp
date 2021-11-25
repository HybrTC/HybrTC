#pragma once

#include <cstdint>
#include <memory>

#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "spdlog.hpp"

#include "../host/socket/socket.h"

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
        // receive a message

        auto msg = connection->recv();

        // deserialize the message
        // auto object = nlohmann::json::from_msgpack(u8p(msg.data()), u8p(msg.data()) + msg.size());

        // SPDLOG_TRACE("recv = {}", object.dump());
        return msg;
    }

    void send(const Message& msg)
    {
        connection->send(msg);
        // SPDLOG_TRACE("sent = {}", object.dump());
        // auto ret = core.send(zmq::buffer(nlohmann::json::to_msgpack(object)));
        // if (ret.has_value())
        // {
        //     bytes_sent += ret.value();
        // }
    }

    void send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const void* payload)
    {
        connection->send(session_id, message_type, payload_len, payload);
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
