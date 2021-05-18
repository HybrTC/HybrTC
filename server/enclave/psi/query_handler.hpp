#pragma once

#include "paillier.hpp"

class QueryHandler
{
  protected:
    PSI::Paillier homo;

  public:
    using database_t = std::vector<std::pair<u32, u32>>;

    void set_public_key(const v8& pubkey)
    {
        homo.load_pubkey(pubkey);
    }

    virtual void load_data(const u32* data_key, const u32* data_val, size_t data_size) = 0;

    virtual auto get_result() -> v8 = 0;

    virtual ~QueryHandler() = default;
};
