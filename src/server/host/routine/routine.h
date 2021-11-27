#pragma once

#include "../psi_context.hpp"

auto client_thread(int port, PSIContext* context) -> std::pair<size_t, size_t>;

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
auto peer_thread(uint16_t port, const char* peer_host, uint16_t peer_port, PSIContext* context)
    -> std::tuple<size_t, size_t, size_t, size_t>;
#endif
