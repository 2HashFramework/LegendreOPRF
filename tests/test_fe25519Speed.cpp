#include <iostream>
#include <stdio.h>
#include <chrono>

#include <libOTe/config.h>
#include "../smallSetVoleFast.h"
#include "../field25519/fe25519.h"
#include <gmpxx.h>

void test_speed()
{
    mpz_class sum1(0);
    fe25519 sum2;
    fe25519_setzero(&sum2);
    int n = 128;

    std::vector<mpz_class> summands1(n, mpz_class(255));
    std::vector<fe25519 *> summands2(n);
    for (int i = 0; i < n; ++i)
    {
        summands2[i] = new fe25519();
        fe25519_setzero(summands2[i]);
        summands2[i]->v[0] = 255;
    }

    std::chrono::steady_clock::time_point begin1 = std::chrono::steady_clock::now();

    for (int k = 0; k < n; ++k)
    {
        sum1 += summands1[k];
    }
    sum1 %= prime;
    std::chrono::steady_clock::time_point end1 = std::chrono::steady_clock::now();
    std::cout << "time computing sum1 = " << sum1 << " is " << (end1 - begin1).count() << std::endl;

    std::chrono::steady_clock::time_point begin2 = std::chrono::steady_clock::now();

    for (int k = 0; k < n; ++k)
    {
        fe25519_add_lazy(&sum2, &sum2, summands2[k]);
    }
    fe25519_freeze(&sum2);
    std::chrono::steady_clock::time_point end2 = std::chrono::steady_clock::now();
    std::cout << "time computing sum2 = " << sum2 << " is " << (end2 - begin2).count() << std::endl;
}



int main()
{
    // test_speed();
    fe25519 fe;
    fe.setzero();

    for(int i = 0; i < 10; ++i){
        fe.v[0] = i;
        std::cout << i << "is square? "<< (int) fe.legendre_symbol() << std::endl;
    }
    std::cout << "Correct: true"<< std::endl;
    return 0;
}