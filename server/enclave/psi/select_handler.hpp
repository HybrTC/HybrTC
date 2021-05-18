#pragma once

#include "crypto/ctr_drbg.hpp"
#include "query_handler.hpp"

class SelectHandler : public QueryHandler
{
  protected:
    database_t local_data;
    sptr<mbedtls::ctr_drbg> rand_ctx;

  public:
    explicit SelectHandler(sptr<mbedtls::ctr_drbg> rand_ctx);

    void load_data(const u32* data_key, const u32* data_val, size_t data_size) override;

    auto get_result() -> v8 override;
};
