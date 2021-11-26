#pragma once

#include <cstdint>
#include <memory>

struct Message
{
    uint32_t session_id = -1;
    uint32_t message_type = -1;
    uint32_t payload_len = -1;
    std::uint8_t* payload = nullptr;

    Message() = default;

    Message(uint32_t session_id, uint32_t message_type, uint32_t payload_len, std::uint8_t* payload)
        : session_id(session_id), message_type(message_type), payload_len(payload_len), payload(payload){};

    ~Message()
    {
        if (payload != nullptr)
        {
            free(payload);
            payload = nullptr;
        }
    }
};

using MessagePtr = std::shared_ptr<Message>;
