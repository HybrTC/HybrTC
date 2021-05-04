#pragma once

#include <cstddef>
#include <utility>
#include "ctr_drbg.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/bignum.h>

class mpi : public internal::
                resource<mbedtls_mpi, &mbedtls_mpi_init, &mbedtls_mpi_free>
{
    static auto eval(
        int (*op)(mbedtls_mpi* X, const mbedtls_mpi* A, const mbedtls_mpi* B),
        const mpi& A,
        const mpi& B) -> mpi&&
    {
        mpi X;
        op(X.get(), A.get(), B.get());
        return std::move(X);
    }

    static auto eval(
        int (*op)(mbedtls_mpi* X, const mbedtls_mpi* A, mbedtls_mpi_sint b),
        const mpi& A,
        const mbedtls_mpi_sint& B) -> mpi&&
    {
        mpi X;
        op(X.get(), A.get(), B);
        return std::move(X);
    }

  public:
    static auto gen_prime(size_t nbits, ctr_drbg& ctr_drbg) -> mpi&&
    {
        int prime_quality =
            nbits > 1024 ? MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR : 0;

        mpi X;
        mbedtls_mpi_gen_prime(
            X.get(),
            nbits,
            prime_quality,
            mbedtls_ctr_drbg_random,
            ctr_drbg.get());

        return std::move(X);
    }

    static auto gen_rand(size_t nbytes, ctr_drbg& ctr_drbg) -> mpi&&
    {
        mpi X;
        mbedtls_mpi_fill_random(
            X.get(), nbytes, mbedtls_ctr_drbg_random, ctr_drbg.get());

        return std::move(X);
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

    auto operator+(const mpi& B) const -> mpi&&
    {
        return eval(mbedtls_mpi_add_mpi, *this, B);
    }

    auto operator+(const mbedtls_mpi_sint& B) const -> mpi&&
    {
        return eval(mbedtls_mpi_add_int, *this, B);
    }

    auto operator-(const mpi& B) const -> mpi&&
    {
        return eval(mbedtls_mpi_sub_mpi, *this, B);
    }

    auto operator-(const mbedtls_mpi_sint& B) const -> mpi&&
    {
        return eval(mbedtls_mpi_sub_int, *this, B);
    }

    auto operator*(const mpi& B) const -> mpi&&
    {
        return eval(mbedtls_mpi_mul_mpi, *this, B);
    }

    auto operator/(const mpi& B) const -> mpi&&
    {
        mpi Q;
        mbedtls_mpi_div_mpi(Q.get(), nullptr, get(), B.get());
        return std::move(Q);
    }

    auto operator%(const mpi& B) const -> mpi&&
    {
        mpi R;
        mbedtls_mpi_div_mpi(nullptr, R.get(), get(), B.get());
        return std::move(R);
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

    [[nodiscard]] auto exp_mod(const mpi& E, const mpi& N) const -> mpi&&
    {
        mpi X;
        mbedtls_mpi_exp_mod(X.get(), get(), E.get(), N.get(), nullptr);
        return std::move(X);
    }

    [[nodiscard]] auto invmod(const mpi& N) const -> mpi&&
    {
        return eval(mbedtls_mpi_inv_mod, *this, N);
    }

    static auto gcd(const mpi& A, const mpi& B) -> mpi&&
    {
        return eval(mbedtls_mpi_gcd, A, B);
    }

    static auto lcm(const mpi& A, const mpi& B) -> mpi&&
    {
        return A * B / gcd(A, B);
    }

    static void swap(mpi& A, mpi& B)
    {
        mbedtls_mpi_swap(A.get(), B.get());
    }
};

} // namespace mbedtls
