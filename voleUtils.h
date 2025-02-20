#pragma once

#ifndef VOLE_UTILS
#define VOLE_UTILS

#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Tools/CoeffCtx.h>
#include "field25519/fe25519.h"
#include <gmpxx.h>

using namespace osuCrypto;

#define NUM_BASE_OT 128
#define OSU_BLOCK_BYTES 16
#define OPRF_OUTPUT_BYTES 32
#define PRIME_BITS 255
#define PRIME_BYTES ((PRIME_BITS + 7) / 8)
#define PRIME_UINT64s ((PRIME_BITS + 63) / 64)
#define PRIME_X 19 // prime = 2^PRIME_BITS - PRIME_X
mpz_class prime("57896044618658097711785492504343953926634992332820282019728792003956564819949");

#define TIC std::chrono::steady_clock::time_point tic_toc_time = std::chrono::steady_clock::now();

#define TOC(A) std::cout << #A << ": " << duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - tic_toc_time).count() << " microseconds"<< std::endl; \
tic_toc_time = std::chrono::steady_clock::now();

#define CTX osuCrypto::CoeffCtxInteger
using Vec = typename CTX::template Vec<block>; 
#define FORMAT osuCrypto::PprfOutputFormat::ByTreeIndex

using namespace osuCrypto;

void random_fe25519(fe25519 *r, PRNG &prng)
{
    unsigned char randomness[PRIME_BYTES];
    prng.get(randomness, PRIME_BYTES);
    fe25519_unpack(r, randomness);
}

void random_mod_p(mpz_class &r, PRNG &prng)
{
    uint64_t randomness[PRIME_UINT64s];
    for (size_t i = 0; i < PRIME_UINT64s; i++)
    {
        randomness[i] = prng.get();
    }

    mpz_import(r.get_mpz_t(), PRIME_UINT64s, 1, sizeof(uint64_t), 1, 0, randomness);
    r %= prime;
}

void write_to_bytes(unsigned char *data, mpz_class x)
{
    size_t bytes_written;
    mpz_export(data, &bytes_written, -1, 1, 1, 0, x.get_mpz_t());
    while (bytes_written < PRIME_BYTES)
    {
        data[bytes_written++] = 0;
    }
}

void write_vec_to_bytes(unsigned char *data, const std::vector<fe25519> &v)
{
    for (auto &vi : v)
    {
        fe25519_pack(data, &vi);
        data += PRIME_BYTES;
    }
}

void write_vec_to_bytesGMP(unsigned char *data, const std::vector<mpz_class> &v)
{
    for (auto &vi : v)
    {
        write_to_bytes(data, vi);
        data += PRIME_BYTES;
    }
}

void read_from_bytes(mpz_class &x, const unsigned char *data)
{
    mpz_import(x.get_mpz_t(), PRIME_BYTES, -1, 1, 1, 0, data);
}

// Reduce mod p if p = 2^n - x for small x
void fast_reduce_mod_p(mpz_class &a)
{
    // these functions shift: https://gmplib.org/manual/Integer-Division
    mpz_class a0, a1;
    mpz_tdiv_q_2exp(a1.get_mpz_t(), a.get_mpz_t(), PRIME_BITS);
    mpz_tdiv_r_2exp(a0.get_mpz_t(), a.get_mpz_t(), PRIME_BITS);
    a = a0 + PRIME_X * a1;
    // get in [0,..,p-1]
    if (a > prime)
    {
        a -= prime;
    }
}

fe25519 dot_product(const std::vector<fe25519> &gamma, const std::vector<fe25519> &vec)
{
    fe25519 out;
    out.setzero();
    for (size_t i = 0; i < vec.size(); i++)
    {
        out += gamma[i]*vec[i];
    }
    out.reduce_add_sub();
    return out;
}

void expand_vec(std::vector<fe25519> &vec, block seed)
{
    PRNG p(seed);
    for (auto vi : vec)
    {
        random_fe25519(&vi, p);
    }
}


void generateF25519VectorFromSeed(std::vector<fe25519> &vec, block &seed)
{
    int expanded_length = vec.size() * PRIME_BYTES;
    unsigned char expanded[expanded_length];
    unsigned char *ptr = expanded;

    PRNG prng(seed);
    prng.get(expanded, expanded_length);
    for (auto &vi: vec)
    {
        vi.unpack(ptr);
        ptr += PRIME_BYTES;
    }
}

#endif