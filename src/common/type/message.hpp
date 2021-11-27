#pragma once

enum MessageType
{
    AttestationRequest = 0x10,
    AttestationResponse = 0x11,
    /* C-S messages */
    QueryRequest = 0x20,
    QueryResponse = 0x21,
    /* S-S messages */
    ComputeRequest = 0x30,
    ComputeResponse = 0x31
};
