#ifndef MOCK_SS_VOLE
#define MOCK_SS_VOLE

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

#include "voleUtils.h"

// o = u + h*v

using namespace osuCrypto;

class MockSmallSetVole
{
public:
    int len;
    int bits;
    int repeat;

    MockSmallSetVole(int len, int bits, int repeat) : len(len), bits(bits), repeat(repeat) {};

    task<> receive(
        std::vector<std::vector<mpz_class>> &o,
        std::vector<unsigned int> &h,
        PRNG &prng,
        Socket &chl)
    {
        block seed = prng.get();
        co_await chl.send(seed);
        PRNG sPrng(seed);

        std::vector<mpz_class> u(len), v(len);

        for (size_t i = 0; i < repeat; i++)
        {
            for (size_t j = 0; j < len; j++)
            {
                random_mod_p(u[j], sPrng);
                random_mod_p(v[j], sPrng);
            }
            h[i] = sPrng.get();
            h[i] %= (1 << bits);

            for (size_t j = 0; j < len; j++)
            {
                o[i][j] = (u[j] + h[i] * v[j]) % prime;
            }
        }
    }

    task<> send(
        std::vector<std::vector<mpz_class>> &u,
        std::vector<std::vector<mpz_class>> &v,
        PRNG &prng,
        Socket &chl)
    {
        block seed;
        co_await chl.recv(seed);
        PRNG sPrng(seed);

        for (size_t i = 0; i < repeat; i++)
        {
            for (size_t j = 0; j < len; j++)
            {
                random_mod_p(u[i][j], sPrng);
                random_mod_p(v[i][j], sPrng);
            }

            // we don't need the value of h, but we need to extract something from the prng to remain consistency with the receiver
            unsigned int h = sPrng.get();
        }
    }
};

#endif
