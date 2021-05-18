#pragma once

#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "common/types.hpp"
#include "spdlog.hpp"

class Socket
{
    zmq::socket_t core;

    Socket(zmq::context_t& io, zmq::socket_type type) : core(io, type)
    {
    }

    size_t bytes_sent = 0;
    size_t bytes_received = 0;

  public:
    static auto listen(zmq::context_t& io, int port) -> Socket
    {
        Socket socket(io, zmq::socket_type::rep);
        socket.core.bind(fmt::format("tcp://*:{}", port));
        return socket;
    }

    static auto connect(zmq::context_t& io, const char* endpoint) -> Socket
    {
        Socket socket(io, zmq::socket_type::req);
        socket.core.connect(endpoint);
        return socket;
    }

    auto recv() -> nlohmann::json
    {
        // receive a message
        zmq::message_t msg;
        auto ret = core.recv(msg, zmq::recv_flags::none);
        if (ret.has_value())
        {
            bytes_received += ret.value();
        }

        // deserialize the message
        auto object = nlohmann::json::from_msgpack(u8p(msg.data()), u8p(msg.data()) + msg.size());

        SPDLOG_TRACE("recv = {}", object.dump());
        return object;
    }

    void send(const nlohmann::json& object)
    {
        SPDLOG_TRACE("sent = {}", object.dump());
        auto ret = core.send(zmq::buffer(nlohmann::json::to_msgpack(object)));
        if (ret.has_value())
        {
            bytes_sent += ret.value();
        }
    }

    auto statistics() -> std::pair<size_t, size_t>
    {
        return {bytes_sent, bytes_received};
    }

    void close()
    {
        core.close();
    }
};
