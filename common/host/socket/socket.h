#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

class SocketConnection;

class Socket
{
  protected:
    int sockfd;

    Socket();

    explicit Socket(int sockfd) : sockfd(sockfd)
    {
    }

  public:
    Socket(const Socket& other);
};

class SocketConnection : Socket
{
    friend class SocketServer;

    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    std::string peer_address;

    explicit SocketConnection(int fd) : Socket(fd)
    {
    }

  public:
    SocketConnection(const char* host, uint16_t port);

    void send(uint32_t data, bool more = false);
    void send(const void* data, size_t size, bool more = false);

    auto recv(void* buffer, size_t size) -> size_t;
    auto recv(size_t size) -> void*;

    [[nodiscard]] auto statistics() const -> std::pair<size_t, size_t>;
    [[nodiscard]] auto get_peer_address() const -> const char*
    {
        return peer_address.c_str();
    }

    ~SocketConnection();
};

class SocketServer : public Socket
{
  public:
    explicit SocketServer(uint16_t port);

    [[nodiscard]] auto accept() const -> SocketConnection;

    ~SocketServer();
};
