#include "socket.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

MessagePtr Message::create(uint32_t session_id, uint32_t message_type, uint32_t payload_len)
{
    void* buf = calloc(sizeof(Message) + payload_len, 1);

    Message& msg = *reinterpret_cast<Message*>(buf);
    msg.session_id = session_id;
    msg.message_type = message_type;
    msg.payload_len = payload_len;

    return MessagePtr((Message*)buf, free);
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
    char errbuf[16];

    // to avoid address already in used
    static const int opt = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // bind 0.0.0.0:port
    struct sockaddr_in addr
    {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = { INADDR_ANY }
    };
    if (::bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        sprintf(errbuf, "bind %u", port);
        perror(errbuf);
        exit(EXIT_FAILURE);
    }

    // listen
    if (::listen(sockfd, 3) < 0)
    {
        sprintf(errbuf, "listen %u", port);
        perror(errbuf);
        exit(EXIT_FAILURE);
    }
}

static void sockaddr_to_str(sockaddr_in& addr, char* dst)
{
    inet_ntop(AF_INET, &addr.sin_addr, dst, sizeof(addr));
    dst += strlen(dst);
    sprintf(dst, ":%u", addr.sin_port);
}

SocketConnection SocketServer::accept() const
{
    struct sockaddr_in addr
    {
        .sin_family = AF_INET, .sin_port = 0, .sin_addr = { 0 }
    };
    socklen_t addr_len = sizeof(addr);

    int peerfd = ::accept(sockfd, (struct sockaddr*)&addr, (socklen_t*)&addr_len);
    if (peerfd < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    SocketConnection conn(peerfd);
    sockaddr_to_str(addr, conn.peer_address);
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
    struct sockaddr_in addr
    {
        .sin_family = AF_INET, .sin_port = htons(port),
    };

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton: address %s not supported", host);
        exit(EXIT_FAILURE);
    }

    if (::connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        char errbuf[32];
        sprintf(errbuf, "connect %s:%d", host, port);
        perror(errbuf);
        exit(EXIT_FAILURE);
    }

    sockaddr_to_str(addr, peer_address);
}

// Send utilities

static bool _check_send_len(ssize_t len)
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
    ssize_t len = ::send(sockfd, (uint8_t*)&msg, sizeof(Message) + msg.payload_len, 0);
    if (_check_send_len(len))
    {
        bytes_sent += len;
    }
}

void SocketConnection::send(uint32_t session_id, uint32_t message_type, uint32_t payload_len, const uint8_t* payload)
{
    for (uint32_t val : {session_id, message_type, payload_len})
    {
        ssize_t len = ::send(sockfd, (uint8_t*)&val, sizeof(val), MSG_MORE);
        if (_check_send_len(len))
        {
            bytes_sent += len;
        }
    }

    ssize_t len = ::send(sockfd, payload, payload_len, 0);
    if (_check_send_len(len))
    {
        bytes_sent += len;
    }
}

static ssize_t recvall(int fd, void* buf, size_t n)
{
    uint8_t* ptr = (uint8_t*)buf;

    ssize_t received = 0;
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
    ssize_t len;

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
    else
    {
        bytes_received += len;
    }

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