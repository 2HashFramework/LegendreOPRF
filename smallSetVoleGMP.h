#pragma once

#include <iostream>
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include <cryptoTools/Crypto/Blake2.h>
#include <sodium.h>
#include <chrono>

#include "voleUtils.h"

// #define FORMAT PprfOutputFormat::ByTreeIndex
// #define CTX CoeffCtxInteger

/*
 Implements the small domain VOLE protocol from
https://eprint.iacr.org/2023/996.pdf Fig. 3
*/

// The subset S_\delta can be of small size. For simplicity, use size as power of 2 because then, one can just use the PPRF for N-1-out-of-N OT from the SoftSpokenVole implementation.
using namespace osuCrypto;
using Vec = typename CTX::template Vec<block>; // I have no clue what this does

void generateFpVectorFromSeed(std::vector<mpz_class> &targets, block &seed, const int len)
{
    // The XOF BLAKE2x seems not implemented in libOTe or sodium. Use Chacha20 instead
    // hash 16 byte seed to get nonce and key for chacha20
    int hashLength = crypto_stream_chacha20_NONCEBYTES + crypto_stream_chacha20_KEYBYTES;
    assert(hashLength < crypto_generichash_BYTES_MAX);
    unsigned char hash[hashLength];

    crypto_generichash(hash, sizeof hash,
                       seed.data(), OSU_BLOCK_BYTES,
                       NULL, 0);
    int expanded_length = len * PRIME_BYTES;
    unsigned char expanded[expanded_length];
    crypto_stream_chacha20(expanded, expanded_length,
                           hash, hash + crypto_stream_salsa20_NONCEBYTES);
    for (int k = 0; k < len; ++k)
    {
        mpz_import(targets[k].get_mpz_t(), PRIME_BYTES, 1, sizeof(u8), 1, 0, expanded + PRIME_BYTES * k);
        targets[k] %= prime;
    }
}

class SmallSetVoleSender
{

public:
    int len;
    int bits;
    int repeat;
    OtSender *otSender;

    SmallSetVoleSender(OtSender *ots, int len, int bits, int repeat)
    {
        otSender = ots;
        this->bits = bits;
        this->repeat = repeat;
        this->len = len;
    }

    ~SmallSetVoleSender()
    {
        delete otSender;
    }

    task<> send(
        std::vector<std::vector<mpz_class>> &u,
        std::vector<std::vector<mpz_class>> &v,
        PRNG &prng,
        Socket &chl)
    {
        // --- Preparing the PPRF ---
        int N = 1 << bits; // Size of the small set S_\delta, also called domain in libOTe
        int depth = bits;
        RegularPprfSender<block, block, CTX> *pprfSender = new RegularPprfSender<block, block, CTX>(N, repeat);

        //--- perform the base OTs. --- need to call them manually, see Pprf_Test.cpp line 205
        int numOTs = pprfSender->baseOtCount();
        std::vector<std::array<block, 2>> sendOTs(numOTs);
        auto proto = otSender->send(sendOTs, prng, chl); // send is randomOT sendChosen is normal OT
        coproto::sync_wait(proto);

        pprfSender->setBase(sendOTs);

        Vec b(N * repeat); // this is where the result leafs should lie. But I don't get why not a std::vec.
        // delta is 0 because it's not used because we also set programPuncturedPoint = false, so I guess delta will be ignored.
        co_await (pprfSender->expand(chl, 0, prng.get(), b, FORMAT, false, 1));

       // Compute u and v from each tree
        u.resize(repeat);
        v.resize(repeat);
        int diff = 0;
        for (int j = 0; j < repeat; ++j)
        {
            std::vector<std::vector<mpz_class>> targets(N);
            u[j].resize(len, mpz_class(0));
            v[j].resize(len, mpz_class(0));
            for (int i = 0; i < N; ++i)
            {
                // targets[i] = PRG(b[i]) \in \Fp^len for each tree j
                targets[i] = std::vector<mpz_class>(len);
                generateFpVectorFromSeed(targets[i], b[N * j + i], len);
            }
            for (int k = 0; k < len; ++k)
            {
                for (int i = 0; i < N; ++i)
                {
                    v[j][k] += targets[i][k];
                }
                v[j][k] %= prime;
            }

            for (int k = 0; k < len; ++k)
            {
                for (int i = 0; i < N; ++i)
                {
                    if (k == 0)
                    {
                    }
                    u[j][k] += targets[i][k] * i;
                }
                u[j][k] %= prime;
            }
            for (int k = 0; k < len; ++k)
            {
                u[j][k] = prime - u[j][k];
            }
        }
    }
};

class SmallSetVoleReceiver
{
public:
    int len;
    int bits;
    int repeat;
    OtReceiver *otrec;

    SmallSetVoleReceiver(OtReceiver *otr, int len, int bits, int repeat)
    {
        otrec = otr;
        this->bits = bits;
        this->repeat = repeat;
        this->len = len;
    }
    ~SmallSetVoleReceiver()
    {
        delete otrec;
    }

    task<> receive(
        std::vector<std::vector<mpz_class>> &o,
        std::vector<mpz_class> &h,
        PRNG &prng,
        Socket &chl)
    {

        // --- Prepare PPRF receiver ---
        CTX ctx;           // not sure if I need this object
        int N = 1 << bits; // Size of the small set S_\delta, also called domain in libOTe
        int depth = bits;
        RegularPprfReceiver<block, block, CTX> *pprfReceiver = new RegularPprfReceiver<block, block, CTX>();
        pprfReceiver->configure(N, repeat);
        int numOTs = pprfReceiver->baseOtCount();
        std::vector<block> recvOTs(numOTs);

        // --- perform OT ---
        BitVector recvBits = pprfReceiver->sampleChoiceBits(prng); // apparently, randomOT only randomizes the messsages not choice bits. So choose randomly.
        auto proto = otrec->receive(recvBits, recvOTs, prng, chl);
        coproto::sync_wait(proto);

        pprfReceiver->setBase(recvOTs);

        // --- Perform PPRF ---
        Vec a(N * repeat);
        std::vector<u64> points(repeat);
        pprfReceiver->getPoints(points, FORMAT);
        co_await (pprfReceiver->expand(chl, a, FORMAT, false, 1));


        // Now, we have to compute PRG(a[i]) to get an Fp^len vector.
        // Compute o and delta from each tree
        o.resize(repeat);
        h.resize(repeat);
        for (int j = 0; j < repeat; ++j)
        {
            std::vector<std::vector<mpz_class>> targets(N);
            o[j].resize(len, mpz_class(0));
            for (int i = 0; i < N; ++i)
            {
                // dont expand at punctured point
                if (points[j] == i)
                {
                    continue;
                }
                // targets[i] = PRG(b[i])
                targets[i] = std::vector<mpz_class>(len);
                generateFpVectorFromSeed(targets[i], a[N * j + i], len);
            }
            for (int k = 0; k < len; ++k)
            {
                for (int i = 0; i < N; ++i)
                {
                    if (points[j] == i)
                    {
                        continue;
                    }
                    if (k == 0)
                    {
                    }
                    int delta = (points[j] - i);
                    o[j][k] += targets[i][k] * delta;
                }
                o[j][k] %= prime;
                if (o[j][k] < 0)
                {
                    o[j][k] += prime; // to always get a value in [0..p-1]
                }
            }
            h[j] = mpz_class(points[j]);
        }
    }
};
