#pragma once

namespace mbedtls
{
enum
{
    BITS_PER_BYTE = 8
};

namespace internal
{
template <class T, void (*init)(T*) = nullptr, void (*clean)(T*) = nullptr>
class resource
{
    T ctx;

  public:
    resource()
    {
        if (init != nullptr)
        {
            init(&ctx);
        }
    }

    resource(const resource&) = delete;

    auto get() -> T*
    {
        return &ctx;
    }

    auto get() const -> const T*
    {
        return &ctx;
    }

    ~resource()
    {
        if (clean != nullptr)
        {
            clean(&ctx);
        }
    }
};
} // namespace internal

} // namespace mbedtls
