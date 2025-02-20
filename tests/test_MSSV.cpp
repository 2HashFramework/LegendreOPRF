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

int main()
{

    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int numVole = 2;

    // The code to be run by the OT receiver.

    int len = 3;
    int small_set_bits = 8;
    int statistical_security_bits = 80;

    cout << "Test Mock Small Set Vole\n";

    int repeat = 1;

    {
        MockSmallSetVole MSSV(len, small_set_bits, repeat);

        std::cout << "repeat:" << MSSV.repeat << std::endl;

        // Define these outside to have access for tests later.
        std::vector<std::vector<mpz_class>> o(repeat, std::vector<mpz_class>(len));
        std::vector<unsigned int> h(repeat);

        auto recverThread = std::thread([&]()
                                        {
            PRNG prng(sysRandomSeed());


            auto proto = MSSV.receive(o, h, prng, sockets[0]);
            coproto::sync_wait(proto);
            usleep(100000);
            
            for (size_t j = 0; j < repeat; j++)
            {
                std::cout  << "Received o: \n";
                for (size_t i = 0; i < len; i++)
                {
                    std::cout << o[j][i] << std::endl;
                }
                std::cout  << "Received h: " << h[j] << std::endl << std::flush;
            } });

        std::vector<std::vector<mpz_class>> u(repeat, std::vector<mpz_class>(len));
        std::vector<std::vector<mpz_class>> v(repeat, std::vector<mpz_class>(len));

        // Send
        PRNG prng(sysRandomSeed());
        auto proto = MSSV.send(u, v, prng, sockets[1]);

        auto r = coproto::sync_wait(macoro::wrap(proto));
        for (size_t j = 0; j < repeat; j++)
        {
            std::cout << "Received u: \n";
            for (size_t i = 0; i < len; i++)
            {
                std::cout << u[j][i] << std::endl;
            }
            std::cout << "Received v: \n";
            for (size_t i = 0; i < len; i++)
            {
                std::cout << v[j][i] << std::endl
                          << std::flush;
            }
        }

        recverThread.join();
        // verify that o = u + h*v
        bool correct = true;
        for (int j = 0; j < repeat; ++j)
        {
            for (int k = 0; k < len; ++k)
            {
                if (o[j][k] % prime != (u[j][k] + h[j] * v[j][k]) % prime)
                {
                    correct = false;
                }
            }
        }
        std::cout << "Correct: " << std::boolalpha << correct << std::endl;
    }
    return 0;
}
