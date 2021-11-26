#pragma once

#include "common/types.hpp"

class QueryHandler
{
  public:
    using database_t = std::vector<std::pair<u32, u32>>;

    virtual void load_data(const u32* data_key, const u32* data_val, size_t data_size) = 0;

    virtual auto get_result() -> std::string = 0;

    virtual ~QueryHandler() = default;
};
