#include <string.h>
#include <stdio.h>
#include <numeric>

#include <libOTe/config.h>

#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"

#include "../MockSmallSetVole.h"
#include "../VolePlusGMP.h"
#include <gmpxx.h>
#include <unistd.h>

using namespace osuCrypto;
using namespace std;

int main()
{
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int numVole = 2;

    int len = 3;
    int small_set_bits = 8;
    int statistical_security_bits = 80;

    cout << "\n\n Test Vole+\n";
    VolePlusGMP VP(len, small_set_bits, statistical_security_bits);

    // Declare all these things outside of the thread to access them later for testing
    std::vector<mpz_class> o(len);
    mpz_class h;
    mpz_class cu, cv;

    std::vector<mpz_class> gammaRec(len);

    auto recverThread = std::thread([&]()
                                    {
        PRNG prng(sysRandomSeed());


        // choose random input
        random_mod_p(h, prng);
        auto proto = VP.receive(h, o, gammaRec, cu, cv, prng, sockets[0]);
        coproto::sync_wait(proto);
        usleep(100000);
        std::cout  << "sent h: " << h << std::endl;
        std::cout  << "Received o: \n";
        for (size_t i = 0; i < len; i++)
        {
            std::cout << o[i] << std::endl;
        }
        std::cout  << "Received c_u:" << cu << std::endl;
        std::cout  << "Received c_v:" << cv << std::endl;
        std::cout  << "Received gamma: \n";
        for (size_t i = 0; i < len; i++)
        {
            std::cout << gammaRec[i] << std::endl;
        } });

    std::vector<mpz_class> u(len), v(len), gammaSender(len);
    u[0] = 1;
    v[1] = 1;
    mpz_class ru, rv;
    ru = 1;
    rv = 1;

    // Send
    PRNG prng(sysRandomSeed());
    auto proto = VP.send(u, v, ru, rv, gammaSender, prng, sockets[1]);

    auto r = coproto::sync_wait(macoro::wrap(proto));
    std::cout << "Sent u: \n";
    for (size_t i = 0; i < len; i++)
    {
        std::cout << u[i] << std::endl;
    }
    std::cout << "Sent v: \n";
    for (size_t i = 0; i < len; i++)
    {
        std::cout << v[i] << std::endl
                  << std::flush;
    }

    recverThread.join();

    bool correct = true;
    // Check VOLE correlation
    for (size_t i = 0; i < len; i++)
    {
        if ((o[i] % prime != (u[i] + h * v[i]) % prime))
        {
            std::cerr << "VOLE+ Correlation wrong." << std::endl;
            correct = false;
        }
    }
    if (gammaSender != gammaRec)
    {
        correct = false;
        std::cerr << "Mismatching gamma." << std::endl;
    }
    // Check inner products
    if (cu % prime != (VP.dot_product(gammaRec, u) + ru) % prime)
    {
        correct = false;
        std::cerr << "Commitment on u wrong." << std::endl;
    }
    if (cv % prime != (VP.dot_product(gammaRec, v) + rv) % prime)
    {
        std::cerr << "Commitment on v wrong." << std::endl;
        correct = false;
    }

    std::cout << "Correct: " << std::boolalpha << correct << std::endl;
}
