#pragma once

#include <iostream>
#include <sodium.h>
#include <libOTe/Base/SimplestOT.h>

#include "field25519/fe25519.h"
#include "voleUtils.h"
#include <immintrin.h>


#define AVX2_ADD

inline
void avx2_expand_and_add(unsigned char *u, unsigned char *v, const block &seed, const size_t len){

    const __m256i oddmask = _mm256_set_epi32(-1,0,-1,0,-1,0,-1,0);
    const __m256i evenmask = _mm256_set_epi32(0,-1,0,-1,0,-1,0,-1);

    PRNG prng(seed);
    for (size_t i = 0; i < len; i++)
    {
        unsigned char data_bytes[32];
        prng.get(data_bytes, 32);

        __m256i even = _mm256_maskload_epi32((const int*) data_bytes, evenmask);
        __m256i odd = _mm256_srli_epi64(_mm256_maskload_epi32((const int*) data_bytes, oddmask), 32);

        __m256i u_even = _mm256_loadu_si256((__m256i*) u);
        __m256i v_even = _mm256_loadu_si256((__m256i*) v);
        __m256i u_odd = _mm256_loadu_si256((__m256i*) (u + 32));
        __m256i v_odd = _mm256_loadu_si256((__m256i*) (v + 32));

        u_odd = _mm256_add_epi64(u_odd, v_odd);
        u_even = _mm256_add_epi64(u_even, v_even);

        v_odd = _mm256_add_epi64(v_odd, odd);
        v_even = _mm256_add_epi64(v_even, even);

        _mm256_storeu_si256((__m256i*) u, u_even);
        _mm256_storeu_si256((__m256i*) v, v_even);
        _mm256_storeu_si256((__m256i*) (u+32), u_odd);
        _mm256_storeu_si256((__m256i*) (v+32), v_odd);

        u += 64;
        v += 64;
    }
}


inline
void avx2_expand_and_add4(unsigned char *u, unsigned char *v, const block &seed1, const block &seed2, const block &seed3, const block &seed4, const size_t len){
    const __m256i oddmask = _mm256_set_epi32(-1,0,-1,0,-1,0,-1,0);
    const __m256i evenmask = _mm256_set_epi32(0,-1,0,-1,0,-1,0,-1);

    PRNG prng1(seed1);
    PRNG prng2(seed2);
    PRNG prng3(seed3);
    PRNG prng4(seed4);

    std::vector<unsigned char> data_vec1(len*32);
    std::vector<unsigned char> data_vec2(len*32);
    std::vector<unsigned char> data_vec3(len*32);
    std::vector<unsigned char> data_vec4(len*32);

    unsigned char *data_bytes1 = data_vec1.data();
    unsigned char *data_bytes2 = data_vec2.data();
    unsigned char *data_bytes3 = data_vec3.data();
    unsigned char *data_bytes4 = data_vec4.data();

    prng1.get(data_bytes1, len*32);
    prng2.get(data_bytes2, len*32);
    prng3.get(data_bytes3, len*32);
    prng4.get(data_bytes4, len*32);

    for (size_t i = 0; i < len; i++)
    {
        __m256i even1 = _mm256_maskload_epi32((const int*) data_bytes1, evenmask);
        __m256i odd1 = _mm256_srli_epi64(_mm256_maskload_epi32((const int*) data_bytes1, oddmask), 32);
        __m256i even2 = _mm256_maskload_epi32((const int*) data_bytes2, evenmask);
        __m256i odd2 = _mm256_srli_epi64(_mm256_maskload_epi32((const int*) data_bytes2, oddmask), 32);
        __m256i even3 = _mm256_maskload_epi32((const int*) data_bytes3, evenmask);
        __m256i odd3 = _mm256_srli_epi64(_mm256_maskload_epi32((const int*) data_bytes3, oddmask), 32);
        __m256i even4 = _mm256_maskload_epi32((const int*) data_bytes4, evenmask);
        __m256i odd4 = _mm256_srli_epi64(_mm256_maskload_epi32((const int*) data_bytes4, oddmask), 32);

        data_bytes1 += 32;
        data_bytes2 += 32;
        data_bytes3 += 32;
        data_bytes4 += 32;

        __m256i u_even = _mm256_loadu_si256((__m256i*) u);
        __m256i v_even = _mm256_loadu_si256((__m256i*) v);
        __m256i u_odd = _mm256_loadu_si256((__m256i*) (u + 32));
        __m256i v_odd = _mm256_loadu_si256((__m256i*) (v + 32));

        u_odd = _mm256_add_epi64(u_odd, v_odd);
        u_even = _mm256_add_epi64(u_even, v_even);
        v_odd = _mm256_add_epi64(v_odd, odd1);
        v_even = _mm256_add_epi64(v_even, even1);

        u_odd = _mm256_add_epi64(u_odd, v_odd);
        u_even = _mm256_add_epi64(u_even, v_even);
        v_odd = _mm256_add_epi64(v_odd, odd2);
        v_even = _mm256_add_epi64(v_even, even2);

        u_odd = _mm256_add_epi64(u_odd, v_odd);
        u_even = _mm256_add_epi64(u_even, v_even);
        v_odd = _mm256_add_epi64(v_odd, odd3);
        v_even = _mm256_add_epi64(v_even, even3);

        u_odd = _mm256_add_epi64(u_odd, v_odd);
        u_even = _mm256_add_epi64(u_even, v_even);
        v_odd = _mm256_add_epi64(v_odd, odd4);
        v_even = _mm256_add_epi64(v_even, even4);

        _mm256_storeu_si256((__m256i*) u, u_even);
        _mm256_storeu_si256((__m256i*) v, v_even);
        _mm256_storeu_si256((__m256i*) (u+32), u_odd);
        _mm256_storeu_si256((__m256i*) (v+32), v_odd);

        u += 64;
        v += 64;
    }
}

void bytes_to_fe25519(unsigned char *bytes, fe25519 & fe){
    uint64_t* data = (uint64_t*) bytes;
    fe.setzero();
    for (size_t i = 0; i < 8; i++)
    {
        fe.v[i*4]   +=  data[i]        % (1 << 16);
        fe.v[i*4+2] += (data[i] >> 16) % (1 << 8);
        fe.v[i*4+3] += (data[i] >> 24);
    }
    fe.reduce_add_sub();
} 


/*
 Implements the small domain VOLE protocol from
https://eprint.iacr.org/2023/996.pdf Fig. 3
*/

// The subset S_\delta can be of small size. For simplicity, use size as power of 2 because then, one can just use the PPRF for N-1-out-of-N OT from the SoftSpokenVole implementation.
using namespace osuCrypto;

class SmallSetVoleSender25519
{

public:
    int len;
    int bits;
    int repeat;

    SmallSetVoleSender25519(int len, int bits, int repeat) :
            len(len),
            bits(bits),
            repeat(repeat)
    {};


    task<> send(
        std::vector<std::vector<fe25519>> &u,
        std::vector<std::vector<fe25519>> &v,
        Vec& b,
        int b_offset,
        PRNG &prng,
        Socket &chl)
    {
        int N = 1 << bits; // Size of the small set S_\delta, also called domain in libOTe
        
        // Compute u and v from each tree
        u = std::vector<std::vector<fe25519>>(repeat, std::vector<fe25519>(len));
        v = std::vector<std::vector<fe25519>>(repeat, std::vector<fe25519>(len));

        // Compute v = -sum_{i=0}^{N-1} t[i] and u = sum_{i=0}^{N-1} i * t[i]
#ifdef AVX2_ADD
        std::vector<unsigned char>u_bytes(len*64);
        std::vector<unsigned char>v_bytes(len*64);
        for (int j = 0; j < repeat; ++j)
        {
            memset(u_bytes.data(), 0, len*64);
            memset(v_bytes.data(), 0, len*64);

            for (int i = N - 4; i >= 0; i-=4)
            {
                avx2_expand_and_add4(u_bytes.data(), v_bytes.data(), b[b_offset*N+ N * j + i + 3], b[b_offset*N + N * j + i + 2], b[b_offset*N + N * j + i + 1], b[b_offset*N + N * j + i], len);
            }

            for (size_t i = 0; i < len; i++)
            {
                bytes_to_fe25519(u_bytes.data() + i * 64, u[j][i]);
                bytes_to_fe25519(v_bytes.data() + i * 64, v[j][i]);
                v[j][i].neg();
            }
        }
#else
        std::vector<fe25519> target(len);
        for (int j = 0; j < repeat; ++j)
        {
            // process (N-1)-th and (N-2)-th vectors
            generateF25519VectorFromSeed(v[j], b[b_offset*N+N * j + N - 1], len);
            generateF25519VectorFromSeed(target, b[b_offset*N + N * j + N - 2], len);
            for (int k = 0; k < len; ++k)
            {
                u[j][k] = v[j][k];
                v[j][k] += target[k];
            }
            
            // do rest of the vectors
            for (int i = N - 3; i >= 0; --i)
            {
                generateF25519VectorFromSeed(target, b[b_offset*N + N * j + i], len);
                for (size_t k = 0; k < len; k++)
                {
                    u[j][k] += v[j][k];
                    v[j][k] += target[k];
                }
            }

            // reduce and negate v
            for (size_t k = 0; k < len; k++)
            {
                u[j][k].reduce_add_sub();
                v[j][k].reduce_add_sub();
                v[j][k].neg();
            }
        }
        #endif
        co_return;
    }
};

class SmallSetVoleReceiver25519
{
public:
    int len;
    int bits;
    int repeat;

    SmallSetVoleReceiver25519(int len, int bits, int repeat) :
        len(len),
        bits(bits),
        repeat(repeat){};
    

    task<> receive(
        std::vector<std::vector<fe25519>> &o,
        std::vector<fe25519> &h,
        Vec& a,
        int a_offset, // point to position of the array that is needed. This allows to use one PPRF for many smallSetVOLEs.
        std::vector<u64>& points, 
        PRNG &prng,
        Socket &chl)
    {
        // --- Prepare PPRF receiver ---
        int depth = bits;
        int N = 1 << bits; // Size of the small set S_\delta, also called domain in libOTe

        std::vector<fe25519> target(len);

        o = std::vector<std::vector<fe25519>>(repeat, std::vector<fe25519>(len));
        h = std::vector<fe25519>(repeat);
        std::vector<fe25519> temp(len);
#ifdef AVX2_ADD
        std::vector<unsigned char>u_bytes(len*64);
        std::vector<unsigned char>v_bytes(len*64);    
#endif
        for (int j = 0; j < repeat; ++j)
        {
            h[j].setzero();
            h[j].v[0] = points[a_offset+j]; // Careful here: We set bits=8 in the paper, so points[j] is in [0,255]. But need to adjust if we change tree depth

#ifdef AVX2_ADD
            memset(u_bytes.data(), 0, len*64);
            memset(v_bytes.data(), 0, len*64);

            for (int i = N - 4; i >= 0; i-=4)
            {
                avx2_expand_and_add4(u_bytes.data(), v_bytes.data(), a[a_offset*N+N * j + i + 3], a[a_offset*N+ N * j + i + 2], a[a_offset*N+ N * j + i + 1], a[a_offset*N+ N * j + i], len);
            }

            for (size_t i = 0; i < len; i++)
            {
                bytes_to_fe25519(u_bytes.data() + i * 64, o[j][i]);
                bytes_to_fe25519(v_bytes.data() + i * 64, temp[i]);
            }
#else
            for (int k = 0; k < len; ++k)
            {
                o[j][k].setzero();
                temp[k].setzero();
            }

            for (int i = N - 1; i >= 0; --i)
            {
                generateF25519VectorFromSeed(target, a[a_offset*N+N * j + i]);
                for( int k=0; k<len; k++){
                    o[j][k] += temp[k];
                    temp[k] += target[k];
                }
            }
#endif
            for (int k = 0; k < len; ++k)
            {
                // todo optimize this multiplication
                temp[k].reduce_add_sub();
                for (size_t l = 0; l < 32; l++)
                {
                    temp[k].v[l] = points[a_offset+j]*temp[k].v[l];
                }
                temp[k].reduce_add_sub();
                
                o[j][k] -= temp[k];
                o[j][k].reduce_add_sub();
            }
        }
    co_return;
    }
};
