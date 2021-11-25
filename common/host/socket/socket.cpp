#include "socket.h"

#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ENDPOINT_MAXLEN 32

#define perr_exit(msg)      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    }

#define pferr_exit(format, ...)                   \
    {                                             \
        std::array<char, BUFSIZ> errbuf;          \
        sprintf(&errbuf[0], format, __VA_ARGS__); \
        perr_exit(errbuf.data());                 \
    }

union sockaddr_u
{
    struct sockaddr addr;
    struct sockaddr_in in;
};

auto Message::create(uint32_t session_id, uint32_t message_type, uint32_t payload_len) -> MessagePtr
{
    void* buf = calloc(sizeof(Message) + payload_len, 1);

    Message& msg = *reinterpret_cast<Message*>(buf);
    msg.session_id = session_id;
    msg.message_type = message_type;
    msg.payload_len = payload_len;

    return MessagePtr(&msg, free);
}

Socket::Socket()
{
    sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
}

SocketServer::SocketServer(uint16_t port) : Socket()
{
    // to avoid address already in used
    static const int opt = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        perr_exit("setsockopt");
    }

    // bind 0.0.0.0:port
    sockaddr_u addr{
        .in = {
            .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {INADDR_ANY}

        }};

    if (::bind(sockfd, &addr.addr, sizeof(addr)) < 0)
    {
        pferr_exit("bind %u", port);
    }

    // listen
    if (::listen(sockfd, 3) < 0)
    {
        pferr_exit("listen %u", port)
    }
}

static auto sockaddr_to_str(sockaddr_in& addr) -> std::string
{
    std::string dst(ENDPOINT_MAXLEN, 0);

    inet_ntop(AF_INET, &addr.sin_addr, &dst[0], sizeof(addr));
    dst.resize(strlen(&dst[0]));
    dst += ':';
    dst += std::to_string(addr.sin_port);

    return dst;
}

auto SocketServer::accept() const -> SocketConnection
{
    sockaddr_u addr{
        .in = {
            .sin_family = AF_INET, .sin_port = 0, .sin_addr = {0}

        }};
    socklen_t addr_len = sizeof(addr);

    int peerfd = ::accept(sockfd, &addr.addr, &addr_len);
    if (peerfd < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    SocketConnection conn(peerfd);
    conn.peer_address = sockaddr_to_str(addr.in);
    return conn;
}

SocketServer::~SocketServer()
{
    if (sockfd > 0)
    {
        puts(__PRETTY_FUNCTION__);
        close(sockfd);
    }
}

// Client connect

SocketConnection::SocketConnection(const char* host, uint16_t port) : Socket()
{
    sockaddr_u addr{
        .in = {
            .sin_family = AF_INET,
            .sin_port = htons(port),

        }};

    if (inet_pton(AF_INET, host, &addr.in.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton: address %s not supported", host);
        exit(EXIT_FAILURE);
    }

    if (::connect(sockfd, &addr.addr, sizeof(addr)) < 0)
    {
        pferr_exit("connect %s:%d", host, port);
    }

    peer_address = sockaddr_to_str(addr.in);
}

// Send utilities

static auto check_send_len(ssize_t len) -> bool
{
    if (len < 0)
    {
        perror("send");
        exit(EXIT_FAILURE);
    }
    else
    {
        return true;
    }
}

void SocketConnection::send(const Message& msg)
{
    ssize_t len = ::send(sockfd, reinterpret_cast<const uint8_t*>(&msg), sizeof(Message) + msg.payload_len, 0);
    if (check_send_len(len))
    {
        bytes_sent += len;
    }
}

void SocketConnection::send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const uint8_t* payload)
{
    for (uint32_t val : {session_id, message_type, payload_len})
    {
        ssize_t len = ::send(sockfd, reinterpret_cast<uint8_t*>(&val), sizeof(val), MSG_MORE);
        if (check_send_len(len))
        {
            bytes_sent += len;
        }
    }

    ssize_t len = ::send(sockfd, payload, payload_len, 0);
    if (check_send_len(len))
    {
        bytes_sent += len;
    }
}

static auto recvall(int fd, void* buf, size_t n) -> size_t
{
    auto* ptr = static_cast<uint8_t*>(buf);

    size_t received = 0;
    while (received < n)
    {
        ssize_t len = recv(fd, ptr + received, n - received, MSG_WAITALL);

        if (len < 0)
        {
            perror("recv");
            exit(EXIT_FAILURE);
        }
        else if (len == 0)
        {
            // Peer has closed
            break;
        }
        else
        {
            received += len;
        }
    }

    return received;
}

// Receive utilities

auto SocketConnection::recv() -> MessagePtr
{
    size_t len;

    struct
    {
        uint32_t session_id;
        uint32_t message_type;
        uint32_t payload_len;
    } hdr;
    len = recvall(sockfd, &hdr, sizeof(hdr));
    if (len == 0)
    {
        return nullptr;
    }
    bytes_received += len;

    auto msg = Message::create(hdr.session_id, hdr.message_type, hdr.payload_len);
    len = recvall(sockfd, msg->payload, msg->payload_len);
    if (len == 0)
    {
        fprintf(stderr, "unexpected missing message body\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        bytes_received += len;
    }

    return msg;
}

auto SocketConnection::statistics() const -> std::pair<size_t, size_t>
{
    return {bytes_sent, bytes_received};
}

SocketConnection::~SocketConnection()
{
    if (sockfd > 0)
    {
        puts(__PRETTY_FUNCTION__);
        close(sockfd);
    }
}