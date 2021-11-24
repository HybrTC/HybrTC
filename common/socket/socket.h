#pragma once

#include <cstdint>
#include <memory>

struct Message
{
    uint32_t session_id;
    uint32_t message_type;
    uint32_t payload_len;
    uint8_t payload[];

    Message() = delete;
    static std::shared_ptr<Message> create(uint32_t session_id, uint32_t message_type, uint32_t payload_len);
};

using MessagePtr = std::shared_ptr<Message>;

class SocketConnection;

class Socket
{
  protected:
    int sockfd;

    Socket();

    Socket(int sockfd) : sockfd(sockfd)
    {
    }
};

class SocketConnection : Socket
{
    friend class SocketServer;

    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    char peer_address[32] = {0};

    SocketConnection(int fd) : Socket(fd)
    {
    }

  public:
    SocketConnection(const char* host, uint16_t port);

    void send(const Message& msg);
    void send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const uint8_t* payload);

    auto recv() -> MessagePtr;
    auto statistics() const -> std::pair<size_t, size_t>;

    auto get_peer_address() const -> const char*
    {
        return peer_address;
    }

    ~SocketConnection();
};

class SocketServer : public Socket
{
  public:
    SocketServer(uint16_t port);

    SocketConnection accept() const;

    ~SocketServer();
};
