#pragma once

#include <string>
#include <vector>

#include "ctr_drbg.hpp"
#include "internal/resource.hpp"
#include "log.h"

namespace mbedtls
{
#include <mbedtls/bignum.h>

class mpi : public internal::
                resource<mbedtls_mpi, &mbedtls_mpi_init, &mbedtls_mpi_free>
{
    static auto eval(
        int (*op)(mbedtls_mpi* X, const mbedtls_mpi* A, const mbedtls_mpi* B),
        const mpi& A,
        const mpi& B) -> mpi
    {
        mpi X;
        op(X.get(), A.get(), B.get());
        return X;
    }

    static auto eval(
        int (*op)(mbedtls_mpi* X, const mbedtls_mpi* A, mbedtls_mpi_sint b),
        const mpi& A,
        const mbedtls_mpi_sint& B) -> mpi
    {
        mpi X;
        op(X.get(), A.get(), B);
        return X;
    }

  public:
    mpi() = default;

    mpi(const mpi& Y)
    {
        mbedtls_mpi_copy(get(), Y.get());
    }

    explicit mpi(const mbedtls_mpi_sint& z)
    {
        mbedtls_mpi_lset(get(), z);
    }

    mpi(const uint8_t* buf, size_t buflen)
    {
        read_binary(buf, buflen);
    }

    static auto gen_prime(size_t nbits, ctr_drbg& ctr_drbg) -> mpi
    {
        mpi X;
        mbedtls_mpi_gen_prime(
            X.get(), nbits, 0, mbedtls_ctr_drbg_random, ctr_drbg.get());

        return X;
    }

    static auto gen_rand(size_t nbytes, ctr_drbg& ctr_drbg) -> mpi
    {
        mpi X;
        mbedtls_mpi_fill_random(
            X.get(), nbytes, mbedtls_ctr_drbg_random, ctr_drbg.get());

        return X;
    }

    [[nodiscard]] auto s() const -> int
    {
        return get()->s;
    }

    [[nodiscard]] auto bitlen() const -> size_t
    {
        return mbedtls_mpi_bitlen(get());
    }

    [[nodiscard]] auto size() const -> size_t
    {
        return mbedtls_mpi_size(get());
    }

    [[nodiscard]] auto get_bit(size_t pos) const -> bool
    {
        return bool(mbedtls_mpi_get_bit(get(), pos));
    }

    void read_binary(const uint8_t* buf, size_t buflen)
    {
        mbedtls_mpi_read_binary(get(), buf, buflen);
    }

    auto write_binary(uint8_t* buf, size_t buflen) const -> int
    {
        return mbedtls_mpi_write_binary(get(), buf, buflen);
    }

    [[nodiscard]] auto to_vector() const -> std::vector<uint8_t>
    {
        std::vector<uint8_t> ret(size(), 0);
        write_binary(&ret[0], ret.size());
        return ret;
    }

    template <class U>
    [[nodiscard]] auto to_unsigned() const -> U
    {
        if (size() > sizeof(U))
        {
            TRACE_ENCLAVE("size = %lu", size());
            abort();
        }
        std::array<uint8_t, sizeof(U)> ret;
        mbedtls_mpi_write_binary_le(get(), &ret[0], ret.size());
        return *reinterpret_cast<const U*>(ret.data());
    }

    [[nodiscard]] auto write_string(int radix) const -> std::string
    {
        size_t olen = 0;
        mbedtls_mpi_write_string(get(), radix, nullptr, 0, &olen);

        std::vector<char> buf(olen, 0);
        mbedtls_mpi_write_string(get(), radix, &buf[0], buf.size(), &olen);

        buf.resize(olen);
        return std::string(buf.begin(), buf.end());
    }

    auto operator=(const mbedtls_mpi_sint& z) -> mpi&
    {
        mbedtls_mpi_lset(get(), z);
        return *this;
    }

    auto operator=(const mpi& Y) -> mpi&
    {
        if (&Y != this)
        {
            mbedtls_mpi_copy(get(), Y.get());
        }
        return *this;
    }

    auto operator+(const mpi& B) const -> mpi
    {
        return eval(mbedtls_mpi_add_mpi, *this, B);
    }

    auto operator+(const mbedtls_mpi_sint& B) const -> mpi
    {
        return eval(mbedtls_mpi_add_int, *this, B);
    }

    auto operator-(const mpi& B) const -> mpi
    {
        return eval(mbedtls_mpi_sub_mpi, *this, B);
    }

    auto operator-(const mbedtls_mpi_sint& B) const -> mpi
    {
        return eval(mbedtls_mpi_sub_int, *this, B);
    }

    auto operator*(const mpi& B) const -> mpi
    {
        return eval(mbedtls_mpi_mul_mpi, *this, B);
    }

    auto operator/(const mpi& B) const -> mpi
    {
        mpi Q;
        mbedtls_mpi_div_mpi(Q.get(), nullptr, get(), B.get());
        return Q;
    }

    auto operator%(const mpi& B) const -> mpi
    {
        mpi R;
        mbedtls_mpi_div_mpi(nullptr, R.get(), get(), B.get());
        return R;
    }

    auto operator>(const mbedtls_mpi_sint& B) const -> bool
    {
        return mbedtls_mpi_cmp_int(get(), B) == 1;
    }

    auto operator==(const mbedtls_mpi_sint& B) const -> bool
    {
        return mbedtls_mpi_cmp_int(get(), B) == 0;
    }

    auto operator<(const mbedtls_mpi_sint& B) const -> bool
    {
        return mbedtls_mpi_cmp_int(get(), B) == -1;
    }

    [[nodiscard]] auto exp_mod(const mpi& E, const mpi& N) const -> mpi
    {
        mpi X;
        mbedtls_mpi_exp_mod(X.get(), get(), E.get(), N.get(), nullptr);
        return X;
    }

    [[nodiscard]] auto invmod(const mpi& N) const -> mpi
    {
        return eval(mbedtls_mpi_inv_mod, *this, N);
    }

    static auto gcd(const mpi& A, const mpi& B) -> mpi
    {
        return eval(mbedtls_mpi_gcd, A, B);
    }

    static auto lcm(const mpi& A, const mpi& B) -> mpi
    {
        return A * B / gcd(A, B);
    }

    static void swap(mpi& A, mpi& B)
    {
        mbedtls_mpi_swap(A.get(), B.get());
    }
};

} // namespace mbedtls
