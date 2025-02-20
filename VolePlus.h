
#ifndef VOLEPLUS
#define VOLEPLUS

#include <coroutine>
#include "libOTe/config.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "coproto/Socket/AsioSocket.h"
#include <stdio.h>
#include "smallSetVoleFast.h"
#include <string>
#include "voleUtils.h"

using namespace osuCrypto;

class VolePlus
{
public:
    int len;
    int small_set_bits;
    int statistical_security_bits;
    int k;

    VolePlus(int len, int small_set_bits, int statistical_security_bits) : len(len),
                                                                           small_set_bits(small_set_bits),
                                                                           statistical_security_bits(statistical_security_bits),
                                                                           k((2 * statistical_security_bits + PRIME_BITS + small_set_bits - 1) / small_set_bits) // computes k parameter
    {
    };

    void expand_gamma(std::vector<fe25519> &gamma, block seed)
    {
        PRNG p(seed);
        gamma.resize(len + 1);
        for (size_t i = 0; i < len; i++)
        {
            random_fe25519(&gamma[i], p);
        }
        gamma[len].setone();
    }

    task<> receive(
        const fe25519 h,
        std::vector<fe25519> &o,
        std::vector<fe25519> &gamma,
        fe25519 &cu,
        fe25519 &cv,
        std::vector<std::vector<fe25519>>& oi,
        std::vector<fe25519>& hi, 
        PRNG &prng,
        Socket &chl)
    {

        // recevieve derandomization and update o_i
        std::vector<unsigned char> buffer(PRIME_BYTES * (k - 1) * (len + 1));
        co_await chl.recv(buffer);

        fe25519 vi_prime;
        for (size_t i = 0; i < k - 1; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                vi_prime.unpack(buffer.data() + (i * (len + 1) + j) * PRIME_BYTES);
                oi[i+1][j] += hi[i+1]*vi_prime;
                oi[i+1][j].reduce_add_sub();
            }
        }

        // send gamma_seed and expand gamma
        block gamma_seed = prng.get();
        co_await chl.send(gamma_seed);
        expand_gamma(gamma, gamma_seed);

        // receive check values and do the checks
        buffer.resize((k + 1) * PRIME_BYTES);
        co_await chl.recv(buffer);
        fe25519 cv1, check;
        cv1.unpack(buffer.data() + k * PRIME_BYTES);
        for (size_t i = 0; i < k; i++)
        {
            check.unpack(buffer.data() + i * PRIME_BYTES);
            check -= dot_product(gamma, oi[i]);
            check.reduce_add_sub();
            check += hi[i]*cv1;
            check.reduce_add_sub();
            // TODO: think about constant timeness?
            check.freeze();
            if (!check.iszero())
            {
                std::cout << "receiver: Check failed! Abort." << std::endl;
                co_return;
            }
        }

        // all checks passed

        // send lambda seed and expand. Compute and send Delta'
        buffer.resize(sizeof(block) + PRIME_BYTES);
        block lambda_seed = prng.get();
        memcpy(buffer.data(), &lambda_seed, sizeof(block));

        std::vector<fe25519> lambda(k);
        generateF25519VectorFromSeed(lambda, lambda_seed);

        fe25519 Delta_prime;
        Delta_prime.setzero();
        for (size_t i = 0; i < k; i++)
        {
            Delta_prime += lambda[i]*hi[i];
            Delta_prime.reduce_add_sub();
        }
        Delta_prime = h - Delta_prime;
        Delta_prime.reduce_add_sub();

        Delta_prime.pack(buffer.data() + sizeof(block));
        co_await chl.send(buffer);

        // receive u' and v'
        buffer.resize(2 * (len + 1) * PRIME_BYTES);
        co_await chl.recv(buffer);

        // compute o
        o.resize(len + 1);
        for (size_t j = 0; j < len + 1; j++)
        {
            o[j] = fe25519();
            o[j].setzero();
        }
        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                o[j] += lambda[i]* oi[i][j];
                o[j].reduce_add_sub();
            }
        }
        fe25519 x;
        std::vector<fe25519> v_prime(len + 1);
        for (size_t j = 0; j < len + 1; j++)
        {
            // u'
            x.unpack(buffer.data() + j * PRIME_BYTES);
            o[j] += x;
            o[j].reduce_add_sub();

            // h*v'
            v_prime[j].unpack(buffer.data() + (len + 1 + j) * PRIME_BYTES);
            o[j] += h*v_prime[j];
            o[j].reduce_add_sub();
        }
        // compute c_v and c_u
        cv = dot_product(gamma, v_prime) + cv1;
        cv.reduce_add_sub();
        cu = dot_product(gamma, o) - (h*cv);
        cu.reduce_add_sub();

        o.resize(len);
    }

    task<> send(
        const std::vector<fe25519> u,
        const std::vector<fe25519> v,
        const fe25519 ru,
        const fe25519 rv,
        std::vector<fe25519> &gamma,
        std::vector<std::vector<fe25519>>& ui,
        std::vector<std::vector<fe25519>>& vi,
        PRNG &prng,
        Socket &chl)
    {

        // compute differences v_i prime and write to buffer
        std::vector<unsigned char> buffer(PRIME_BYTES * (k - 1) * (len + 1));

        for (size_t i = 1; i < k; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                fe25519 tmp = (vi[0][j]- vi[i][j]);
                tmp.reduce_add_sub();
                tmp.pack(buffer.data() + ((i - 1) * (len + 1) + j) * PRIME_BYTES);
            }
        }

        // send derandomizatoin
        co_await chl.send(buffer);

        // receive gamma_seed and expand
        block gamma_seed;
        co_await chl.recv(gamma_seed);
        PRNG lambda_prng(gamma_seed);
        expand_gamma(gamma, gamma_seed);

        // compute c_u_i and c_v and write to buffer
        buffer.resize((k + 1) * PRIME_BYTES);
        fe25519 check_value;
        for (size_t i = 0; i < k; i++)
        {
            check_value = dot_product(gamma, ui[i]);
            check_value.pack(buffer.data() + i * PRIME_BYTES);
        }
        check_value = dot_product(gamma, vi[0]);
        check_value.pack(buffer.data() + k * PRIME_BYTES);

        // send check values
        co_await chl.send(buffer);

        // receive lambda_seed and expand, receive and Delta'
        buffer.resize(sizeof(block) + PRIME_BYTES);
        co_await chl.recv(buffer);

        block lambda_seed;
        memcpy((void *)&lambda_seed, buffer.data(), sizeof(block));
        std::vector<fe25519> lambda(k);
        generateF25519VectorFromSeed(lambda, lambda_seed);
        fe25519 Delta_prime;
        Delta_prime.unpack( buffer.data() + sizeof(block));

        // compute u' and v' and send;

        std::vector<fe25519> u_prime(len + 1, fe25519());
        std::vector<fe25519> v_prime(len + 1, fe25519());
        fe25519 tmp;
        for (size_t j = 0; j < len + 1; j++)
        {
            u_prime[j].setzero();
            v_prime[j].setzero();
            for (size_t i = 0; i < k; i++)
            {
                u_prime[j] += lambda[i] * ui[i][j];
                u_prime[j].reduce_add_sub();
            }
        }

        for (size_t j = 0; j < len + 1; j++)
        {
            u_prime[j] = (Delta_prime* vi[0][j]) - u_prime[j];
            u_prime[j].reduce_add_sub();
        }

        for (size_t j = 0; j < len; j++)
        {
            u_prime[j] += u[j];
            u_prime[j].reduce_add_sub();

            v_prime[j]= v[j]- vi[0][j];
            v_prime[j].reduce_add_sub();
        }

        u_prime[len] +=  ru;
        u_prime[len].reduce_add_sub();

        v_prime[len] = rv - vi[0][len];
        v_prime[len].reduce_add_sub();

        buffer.resize(2 * (len + 1) * PRIME_BYTES);
        write_vec_to_bytes(buffer.data(), u_prime);
        write_vec_to_bytes(buffer.data() + (len + 1) * PRIME_BYTES, v_prime);

        co_await chl.send(buffer);
    }
};

#endif
