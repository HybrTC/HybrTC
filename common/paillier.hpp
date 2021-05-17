#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/types.hpp"
#include "crypto/bignum.hpp"
#include "crypto/ctr_drbg.hpp"
#include "sgx/log.h"

namespace PSI
{
using mbedtls::ctr_drbg;
using mbedtls::mpi;

class Paillier
{
    struct pubkey_t
    {
        unsigned bits = 0;
        mpi n;
        mpi g;
        mpi n_sq;

        auto complete() -> bool
        {
            if (bits == 0 || !n.get_bit(bits - 1))
            {
                TRACE_ENCLAVE("bits = %u ; n.get_bit(bits) = %d", bits, n.get_bit(bits - 1));
                return false;
            }

            if (g.bitlen() == 0)
            {
                g = n + 1;
            }

            n_sq = n * n;

            return true;
        }

        struct _dump
        {
            uint32_t nbits;
            uint32_t n_sz;
            uint32_t g_sz;
            uint8_t data[];
        };

        [[nodiscard]] auto dump() const -> v8
        {
            v8 buffer(sizeof(_dump) + n.size() + g.size(), 0);
            _dump& dump = *reinterpret_cast<_dump*>(&buffer[0]);

            dump.nbits = bits;
            dump.n_sz = n.size();
            dump.g_sz = g.size();

            n.write_binary(dump.data, dump.n_sz);
            g.write_binary(dump.data + dump.n_sz, dump.g_sz);

            return buffer;
        }

        void load(const uint8_t* pk, size_t pk_size)
        {
            const _dump& dump = *reinterpret_cast<const _dump*>(pk);
            if (pk_size != sizeof(_dump) + dump.n_sz + dump.g_sz)
            {
                TRACE_ENCLAVE("load key failed");
                abort();
            }

            bits = dump.nbits;
            n.read_binary(dump.data, dump.n_sz);
            g.read_binary(dump.data + dump.n_sz, dump.g_sz);
            complete();
        }
    };

    struct prvkey_t
    {
        mpi λ;
        mpi μ;

        void complete(const pubkey_t& pub)
        {
            μ = ((pub.g.exp_mod(λ, pub.n_sq) - 1) / pub.n).invmod(pub.n);
        }
    };

  private:
    pubkey_t pubkey;
    prvkey_t prvkey;

  public:
    void keygen(size_t nbits, ctr_drbg& ctr_drbg)
    {
        mpi P;
        mpi Q;

        do
        {
            P = mpi::gen_prime(nbits >> 1, ctr_drbg);
            Q = mpi::gen_prime(nbits >> 1, ctr_drbg);

            /* using p,q of equivalent length, a simpler variant of the key
             * generation */
            if (P.bitlen() != Q.bitlen())
            {
                continue;
            }

            /* make sure the difference between p and q is not too small (FIPS
             * 186-4 §B.3.3 step 5.4) */
            if ((P - Q).bitlen() <= ((nbits >= 200) ? ((nbits >> 1) - 99) : 0))
            {
                continue;
            }

            pubkey.n = P * Q;
        } while (!pubkey.n.get_bit(nbits - 1));

        pubkey.bits = nbits;
        pubkey.complete();

        prvkey.λ = mpi::lcm(P - 1, Q - 1);
        prvkey.complete(pubkey);
    }

    [[nodiscard]] auto dump_pubkey() const -> v8
    {
        return pubkey.dump();
    }

    void load_pubkey(const v8& pk)
    {
        return pubkey.load(pk.data(), pk.size());
    }

    void load_pubkey(const uint8_t* pk, size_t pk_size)
    {
        return pubkey.load(pk, pk_size);
    }

    auto encrypt(const uint32_t& plaintext, ctr_drbg& ctr_drbg) const -> mpi
    {
        return encrypt(mpi(plaintext), ctr_drbg);
    }

    auto encrypt(const mpi& plaintext, ctr_drbg& ctr_drbg) const -> mpi
    {
        if (pubkey.bits == 0)
        {
            TRACE_ENCLAVE("pubkey.bits = %u", pubkey.bits);
            abort();
        }

        mpi r = mpi::gen_rand(pubkey.bits >> 3, ctr_drbg);

        return (pubkey.g.exp_mod(plaintext, pubkey.n_sq) * r.exp_mod(pubkey.n, pubkey.n_sq)) % pubkey.n_sq;
    }

    [[nodiscard]] auto decrypt(const mpi& ciphertext) const -> mpi
    {
        return ((((ciphertext.exp_mod(prvkey.λ, pubkey.n_sq)) - 1) / pubkey.n) * prvkey.μ) % pubkey.n;
    }

    [[nodiscard]] auto add(const mpi& A, const mpi& B) const -> mpi
    {
        return (A * B) % pubkey.n_sq;
    }
};
} // namespace PSI
