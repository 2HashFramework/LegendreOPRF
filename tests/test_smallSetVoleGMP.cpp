#include <iostream>
#include <stdio.h>
#include <chrono>

#include <libOTe/config.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/SimplestOT.h>
#include "../smallSetVoleGMP.h"

void test_speed()
{
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int len = 128;
    int bits = 8;
    int numTrees = 8; // Actually, RegularPprf.h line 37 says this must be a multiple of 8. But I tried it with different numbers and it did not obviously crash or anything.
    int nrTrials = 10;
    double diff = 0;
    for (int i = 0; i < nrTrials; ++i)
    {
        std::cout << "Test trial nr " << i << " started." << std::endl;
        std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

        // The code to be run by the receiver.
        std::vector<std::vector<mpz_class>> o;
        std::vector<mpz_class> h;
        auto recverThread = std::thread([&]()
                                        {
            PRNG prngRec(sysRandomSeed());
            OtReceiver* otrec = new SimplestOT();
            SmallSetVoleReceiver rec(otrec,len,bits,numTrees); 
            auto protoRec = rec.receive(o, h, prngRec,sockets[0]);
            macoro::sync_wait(std::move(protoRec)); });
        PRNG prng(sysRandomSeed());

        OtSender *otsend = new SimplestOT();
        SmallSetVoleSender sender(otsend, len, bits, numTrees);
        std::vector<std::vector<mpz_class>> u;
        std::vector<std::vector<mpz_class>> v;
        auto protoSend = sender.send(u, v, prng, sockets[1]);
        macoro::sync_wait(std::move(protoSend));

        recverThread.join();
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        diff += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    std::cout << "Time difference avg = " << diff / nrTrials << "[µs]" << std::endl;
}

void test_correctness()
{
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int len = 3;
    int bits = 2;
    int numTrees = 1; // Actually, RegularPprf.h line 37 says this must be a multiple of 8. But I tried it with different numbers and it did not obviously crash or anything.

    // The code to be run by the receiver.
    std::vector<std::vector<mpz_class>> o;
    std::vector<mpz_class> h;
    auto recverThread = std::thread([&]()
                                    {
        PRNG prngRec(sysRandomSeed());
        OtReceiver* otrec = new SimplestOT();
        SmallSetVoleReceiver rec(otrec,len,bits,numTrees); 
        auto protoRec = rec.receive(o, h, prngRec,sockets[0]);
        macoro::sync_wait(std::move(protoRec)); });
    PRNG prng(sysRandomSeed());

    OtSender *otsend = new SimplestOT();
    SmallSetVoleSender sender(otsend, len, bits, numTrees);
    std::vector<std::vector<mpz_class>> u;
    std::vector<std::vector<mpz_class>> v;
    auto protoSend = sender.send(u, v, prng, sockets[1]);
    macoro::sync_wait(std::move(protoSend));

    recverThread.join();

    // verify that o = u + h*v
    bool correct = true;
    for (int j = 0; j < numTrees; ++j)
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

int main()
{
    test_speed();
    test_correctness();

    return 0;
}