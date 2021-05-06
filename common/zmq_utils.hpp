#pragma once

#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "common/types.hpp"

static auto listen(zmq::context_t& io, int port) -> zmq::socket_t
{
    zmq::socket_t socket(io, zmq::socket_type::rep);
    socket.bind(fmt::format("tcp://*:{}", port));
    return socket;
}

static auto connect(zmq::context_t& io, const char* endpoint) -> zmq::socket_t
{
    zmq::socket_t socket(io, zmq::socket_type::req);
    socket.connect(endpoint);
    return socket;
}

static auto recv(zmq::socket_t& socket) -> nlohmann::json
{
    // receive a message
    zmq::message_t msg;
    (void)socket.recv(msg, zmq::recv_flags::none);

    // deserialize the message
    return nlohmann::json::from_msgpack(
        u8p(msg.data()), u8p(msg.data()) + msg.size());
}

static void send(zmq::socket_t& socket, const nlohmann::json& object)
{
    (void)socket.send(zmq::buffer(nlohmann::json::to_msgpack(object)));
}