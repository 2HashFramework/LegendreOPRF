#include <chrono>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <numeric>

#include <libOTe/config.h>

#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"

#include "../MockSmallSetVole.h"
#include "../VolePlus.h"
#include <gmpxx.h>
#include <unistd.h>

using namespace osuCrypto;
using namespace std;

void test_speed()
{
    PRNG prng(block(2024));
    int repeats = 10000;
    // prepare numbers to reduce
    std::vector<mpz_class> a(repeats), b(repeats);
    for (int i = 0; i < repeats; ++i)
    {
        uint64_t randomness[PRIME_UINT64s + 1];
        for (size_t i = 0; i < PRIME_UINT64s + 1; i++)
        {
            randomness[i] = prng.get();
        }

        mpz_import(a[i].get_mpz_t(), PRIME_UINT64s, 1, sizeof(uint64_t), 1, 0, randomness);
        b[i] = a[i];
    }

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    for (int i = 0; i < repeats; ++i)
    {
        fast_reduce_mod_p(a[i]);
    }
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::cout << "Time difference fast method = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;

    std::chrono::steady_clock::time_point begin2 = std::chrono::steady_clock::now();
    for (int i = 0; i < repeats; ++i)
    {
        b[i] %= prime;
    }
    std::chrono::steady_clock::time_point end2 = std::chrono::steady_clock::now();
    std::cout << "Time difference normal reduction = " << std::chrono::duration_cast<std::chrono::microseconds>(end2 - begin2).count() << "[µs]" << std::endl;
}

int main()
{
    test_speed();
    PRNG prng(block(2024));
    bool correct = true;
    for (int i = 0; i < 1000; ++i)
    {
        mpz_class a, b;
        uint64_t randomness[PRIME_UINT64s + 1];
        for (size_t i = 0; i < PRIME_UINT64s + 1; i++)
        {
            randomness[i] = prng.get();
        }

        mpz_import(a.get_mpz_t(), PRIME_UINT64s, 1, sizeof(uint64_t), 1, 0, randomness);
        b = a;
        fast_reduce_mod_p(a);
        if (b % prime != a)
        {
            std::cerr << "a = " << a << std::endl;
            std::cerr << "b mod p = " << (b % prime) << std::endl;
            correct = false;
        }
    }

    std::cout << "Correct: " << std::boolalpha << correct << std::endl;
    return 0;
}
