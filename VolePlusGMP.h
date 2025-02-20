
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
#include <gmpxx.h>
// #include "MockSmallSetVole.h"
#include "smallSetVoleGMP.h"
#include <libOTe/Base/SimplestOT.h>
#include <string>

using namespace osuCrypto;

class VolePlusGMP
{
public:
    int len;
    int small_set_bits;
    int statistical_security_bits;
    int k;
    SmallSetVoleSender *SSVsender;
    SmallSetVoleReceiver *SSVreceiver;

    VolePlusGMP(int len, int small_set_bits, int statistical_security_bits) : len(len),
                                                                              small_set_bits(small_set_bits),
                                                                              statistical_security_bits(statistical_security_bits),
                                                                              k((2 * statistical_security_bits + PRIME_BITS + small_set_bits - 1) / small_set_bits) // computes k parameter
    {
        OtReceiver *otr = new SimplestOT();
        OtSender *ots = new SimplestOT();
        SSVsender = new SmallSetVoleSender(ots, len + 1, small_set_bits, k);
        SSVreceiver = new SmallSetVoleReceiver(otr, len + 1, small_set_bits, k);
        std::cout << "Vole+ k parameter: " << k << std::endl;
    };

    void expand_gamma(std::vector<mpz_class> &gamma, block seed)
    {
        PRNG p(seed);
        gamma.resize(len);
        for (size_t i = 0; i < len; i++)
        {
            random_mod_p(gamma[i], p);
        }
    }

    void expand_lambda(std::vector<mpz_class> &lambda, block seed)
    {
        PRNG p(seed);
        lambda.resize(k);
        for (size_t i = 0; i < k; i++)
        {
            random_mod_p(lambda[i], p);
        }
    }

    mpz_class dot_product(const std::vector<mpz_class> &gamma, const std::vector<mpz_class> &vec)
    {
        mpz_class out = vec[len];
        for (size_t i = 0; i < len; i++)
        {
            out += gamma[i] * vec[i];
        }
        return out % prime;
    }

    task<> receive(
        const mpz_class h,
        std::vector<mpz_class> &o,
        std::vector<mpz_class> &gamma,
        mpz_class &cu,
        mpz_class &cv,
        PRNG &prng,
        Socket &chl)
    {
        // run the small set VOLE protocol
        std::vector<std::vector<mpz_class>> oi(k, std::vector<mpz_class>(len + 1));
        std::vector<mpz_class> hi(k);
        auto proto = SSVreceiver->receive(oi, hi, prng, chl);
        auto r = coproto::sync_wait(macoro::wrap(proto));

        // recevieve derandomization and update o_i
        std::vector<unsigned char> buffer(PRIME_BYTES * (k - 1) * (len + 1));
        co_await chl.recv(buffer);

        mpz_class vi_prime;
        for (size_t i = 0; i < k - 1; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                read_from_bytes(vi_prime, buffer.data() + (i * (len + 1) + j) * PRIME_BYTES);
                oi[i + 1][j] += hi[i + 1] * vi_prime;
                oi[i + 1][j] %= prime;
            }
        }

        // send gamma_seed and expand gamma
        block gamma_seed = prng.get();
        co_await chl.send(gamma_seed);
        expand_gamma(gamma, gamma_seed);

        // receive check values and do the checks
        buffer.resize((k + 1) * PRIME_BYTES);
        co_await chl.recv(buffer);
        mpz_class cv1, check;
        read_from_bytes(cv1, buffer.data() + k * PRIME_BYTES);
        for (size_t i = 0; i < k; i++)
        {
            read_from_bytes(check, buffer.data() + i * PRIME_BYTES);
            check += prime - dot_product(gamma, oi[i]);
            check += hi[i] * cv1;
            check %= prime;
            // TODO: think about constant timeness?
            if (check != 0)
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

        std::vector<mpz_class> lambda;
        expand_lambda(lambda, lambda_seed);

        mpz_class Delta_prime = 0;
        for (size_t i = 0; i < k; i++)
        {
            Delta_prime += lambda[i] * hi[i];
        }
        Delta_prime %= prime;
        Delta_prime = (h + prime - Delta_prime) % prime;

        write_to_bytes(buffer.data() + sizeof(block), Delta_prime);
        co_await chl.send(buffer);

        // receive u' and v'
        buffer.resize(2 * (len + 1) * PRIME_BYTES);
        co_await chl.recv(buffer);
        std::cout << "receiver: u' and v' received." << std::endl;

        // compute o
        o.resize(len + 1);
        std::fill(o.begin(), o.end(), 0);
        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                o[j] += lambda[i] * oi[i][j];
            }
        }
        mpz_class x;
        std::vector<mpz_class> v_prime(len + 1);
        for (size_t j = 0; j < len + 1; j++)
        {
            // u'
            read_from_bytes(x, buffer.data() + j * PRIME_BYTES);
            o[j] += x;

            // h*v'
            read_from_bytes(v_prime[j], buffer.data() + (len + 1 + j) * PRIME_BYTES);
            o[j] += h * v_prime[j];
            o[j] %= prime;
        }

        // compute c_v and c_u
        cv = (cv1 + dot_product(gamma, v_prime)) % prime;
        cu = (dot_product(gamma, o) + prime - (h * cv) % prime) % prime;

        o.resize(len);
    }

    task<> send(
        const std::vector<mpz_class> u,
        const std::vector<mpz_class> v,
        const mpz_class ru,
        const mpz_class rv,
        std::vector<mpz_class> &gamma,
        PRNG &prng,
        Socket &chl)
    {
        // k vectors of length len+1
        std::vector<std::vector<mpz_class>> ui(k, std::vector<mpz_class>(len + 1));
        std::vector<std::vector<mpz_class>> vi(k, std::vector<mpz_class>(len + 1));

        // run the small set VOLE protocol
        auto proto = SSVsender->send(ui, vi, prng, chl);
        auto r = coproto::sync_wait(macoro::wrap(proto));

        // compute differences v_i prime and write to buffer
        std::vector<unsigned char> buffer(PRIME_BYTES * (k - 1) * (len + 1));
        for (size_t i = 1; i < k; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                write_to_bytes(buffer.data() + ((i - 1) * (len + 1) + j) * PRIME_BYTES, (prime + vi[0][j] - vi[i][j]) % prime);
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
        mpz_class check_value;
        for (size_t i = 0; i < k; i++)
        {
            check_value = dot_product(gamma, ui[i]);
            write_to_bytes(buffer.data() + i * PRIME_BYTES, check_value);
        }
        check_value = dot_product(gamma, vi[0]);
        write_to_bytes(buffer.data() + k * PRIME_BYTES, check_value);

        // send check values
        co_await chl.send(buffer);

        // receive lambda_seed and expand, receive and Delta'
        buffer.resize(sizeof(block) + PRIME_BYTES);
        co_await chl.recv(buffer);

        block lambda_seed;
        memcpy((void *)&lambda_seed, buffer.data(), sizeof(block));
        std::vector<mpz_class> lambda;
        expand_lambda(lambda, lambda_seed);

        mpz_class Delta_prime;
        read_from_bytes(Delta_prime, buffer.data() + sizeof(block));

        // compute u' and v' and send;

        std::vector<mpz_class> u_prime(len + 1);
        std::vector<mpz_class> v_prime(len + 1);

        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < len + 1; j++)
            {
                u_prime[j] += lambda[i] * ui[i][j];
            }
        }

        for (size_t j = 0; j < len + 1; j++)
        {
            u_prime[j] = prime - (u_prime[j] % prime) + Delta_prime * vi[0][j];
        }

        for (size_t j = 0; j < len; j++)
        {
            u_prime[j] += u[j];
            u_prime[j] %= prime;

            v_prime[j] = (prime - vi[0][j] + v[j]) % prime;
        }

        u_prime[len] += ru;
        u_prime[len] %= prime;

        v_prime[len] = (prime - vi[0][len] + rv) % prime;

        buffer.resize(2 * (len + 1) * PRIME_BYTES);
        write_vec_to_bytesGMP(buffer.data(), u_prime);
        write_vec_to_bytesGMP(buffer.data() + (len + 1) * PRIME_BYTES, v_prime);

        co_await chl.send(buffer);
    }
};

#endif
