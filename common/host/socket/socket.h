#pragma once

#include <cstdint>
#include <memory>
#include <string>

struct Message
{
    uint32_t session_id;
    uint32_t message_type;
    uint32_t payload_len;
    uint8_t payload[]; // NOLINT(modernize-avoid-c-arrays)

    Message() = delete;
    static auto create(uint32_t session_id, uint32_t message_type, uint32_t payload_len) -> std::shared_ptr<Message>;
};

using MessagePtr = std::shared_ptr<Message>;

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

    void send(const Message& msg);
    void send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const void* payload);

    auto recv() -> MessagePtr;
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
