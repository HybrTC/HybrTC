#include "socket.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <system_error>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ENDPOINT_MAXLEN 32

#define TID syscall(__NR_gettid)

#define perr_exit(msg)                                                         \
    {                                                                          \
        std::array<char, BUFSIZ> errbuf;                                       \
        sprintf(&errbuf[0], "[%ld] " msg, TID);                                \
        throw std::system_error(errno, std::system_category(), errbuf.data()); \
        exit(EXIT_FAILURE);                                                    \
    }

#define pferr_exit(format, ...)                                                \
    {                                                                          \
        std::array<char, BUFSIZ> errbuf;                                       \
        sprintf(&errbuf[0], "[%ld] " format, TID, __VA_ARGS__);                \
        throw std::system_error(errno, std::system_category(), errbuf.data()); \
        exit(EXIT_FAILURE);                                                    \
    }

union sockaddr_u
{
    struct sockaddr addr;
    struct sockaddr_in in;
};

Socket::Socket()
{
    sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perr_exit("socket");
    }
}

Socket::Socket(const Socket& other)
{
    sockfd = dup(other.sockfd);
}

SocketServer::SocketServer(uint16_t port)
{
    // to avoid address already in used
    static const int opt = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        perr_exit("setsockopt");
    }

    // bind 0.0.0.0:port
    sockaddr_u addr{.in = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {INADDR_ANY}, .sin_zero = {0}}};

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
    sockaddr_u addr{.in = {.sin_family = AF_INET, .sin_port = 0, .sin_addr = {0}, .sin_zero = {0}}};
    socklen_t addr_len = sizeof(addr);

    int peerfd = ::accept(sockfd, &addr.addr, &addr_len);
    if (peerfd < 0)
    {
        perr_exit("accept");
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
        close(sockfd);
    }
}

// Client connect

SocketConnection::SocketConnection(const char* host, uint16_t port)
{
    sockaddr_u addr{.in = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {0}, .sin_zero = {0}}};
    if (inet_pton(AF_INET, host, &addr.in.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton: address %s not supported", host);
        exit(EXIT_FAILURE);
    }

    int retry = 3;
    int ret = 0;

    while ((ret = ::connect(sockfd, &addr.addr, sizeof(addr))) < 0)
    {
        if ((retry--) > 0 && errno == ECONNREFUSED)
        {
            sleep(1);
        }
        else
        {
            pferr_exit("connect %s:%d", host, port);
        }
    }

    peer_address = sockaddr_to_str(addr.in);
}

// Send utilities

static auto check_send_len(ssize_t len) -> bool
{
    if (len < 0)
    {
        perr_exit("send");
    }
    else
    {
        return true;
    }
}

void SocketConnection::send(uint32_t data, bool more)
{
    return send(reinterpret_cast<uint8_t*>(&data), sizeof(uint32_t), more);
}

void SocketConnection::send(const void* data, size_t size, bool more)
{
    ssize_t len = ::send(sockfd, data, size, more ? MSG_MORE : 0);
    if (check_send_len(len))
    {
        bytes_sent += len;
    }
}

// Receive utilities

auto SocketConnection::recv(void* buffer, size_t size) -> size_t
{
    auto* ptr = static_cast<uint8_t*>(buffer);

    size_t received = 0;
    while (received < size)
    {
        ssize_t len = ::recv(sockfd, ptr + received, size - received, MSG_WAITALL);

        if (len < 0)
        {
            perr_exit("recv")
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

auto SocketConnection::recv(size_t size) -> void*
{
    void* buffer = calloc(size, 1);
    if (buffer == nullptr)
    {
        abort();
    }

    if (recv(buffer, size) == 0)
    {
        free(buffer);
        buffer = nullptr;
        return nullptr;
    }

    return buffer;
}

auto SocketConnection::statistics() const -> std::pair<size_t, size_t>
{
    return {bytes_sent, bytes_received};
}

SocketConnection::~SocketConnection()
{
    if (sockfd > 0)
    {
        close(sockfd);
    }
}
