#pragma once

#include "../psi_context.hpp"
#include "host/TxSocket.hpp"

auto attestation_servant(TxSocket& server, PSIContext& context) -> u32;

#if PSI_AGGREGATE_POLICY != PSI_AGGREAGATE_SELECT
auto attestation_initiator(TxSocket& client, PSIContext& context) -> u32;
#endif
