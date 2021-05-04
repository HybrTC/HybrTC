#pragma once

#include <vector>

#include "crypto/bignum.hpp"
#include "crypto/ctr_drbg.hpp"

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
            if (bits == 0 || !n.get_bit(bits))
            {
                return false;
            }

            g = n + 1;
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

        [[nodiscard]] auto dump() const -> std::vector<uint8_t>
        {
            std::vector<uint8_t> buffer(sizeof(_dump) + n.size() + g.size(), 0);
            _dump& dump = *reinterpret_cast<_dump*>(&buffer[0]);

            dump.nbits = bits;
            dump.n_sz = n.size();
            dump.g_sz = g.size();

            n.write_binary(dump.data, dump.n_sz);
            g.write_binary(dump.data + dump.n_sz, dump.g_sz);

            return buffer;
        }

        void load(const std::vector<uint8_t>& buffer)
        {
            const _dump& dump = *reinterpret_cast<const _dump*>(buffer.data());
            n.read_binary(dump.data, dump.n_sz);
            g.read_binary(dump.data + dump.n_sz, dump.g_sz);
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
    }

    auto encrypt(const uint32_t& plaintext, ctr_drbg& ctr_drbg) const
        -> std::vector<uint8_t>
    {
        return encrypt(mpi(plaintext), ctr_drbg);
    }

    auto encrypt(const mpi& plaintext, ctr_drbg& ctr_drbg) const
        -> std::vector<uint8_t>
    {
        mpi&& r = mpi::gen_rand(pubkey.bits >> 3, ctr_drbg);

        mpi&& c = (pubkey.g.exp_mod(plaintext, pubkey.n_sq) *
                   r.exp_mod(pubkey.n, pubkey.n_sq)) %
                  pubkey.n_sq;

        std::vector<uint8_t> ret(c.size(), 0);
        c.write_binary(&ret[0], 0);
        return ret;
    }

    [[nodiscard]] auto decrypt(const mpi& ciphertext) const
        -> std::vector<uint8_t>
    {
        mpi&& p =
            ((((ciphertext.exp_mod(prvkey.λ, pubkey.n_sq)) - 1) / pubkey.n) *
             prvkey.μ) %
            pubkey.n;

        std::vector<uint8_t> ret(p.size(), 0);
        p.write_binary(&ret[0], 0);
        return ret;
    }
};
} // namespace PSI
