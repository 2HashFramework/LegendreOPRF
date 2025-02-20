#include <iostream>
#include <stdio.h>
#include <chrono>

#include <libOTe/config.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/SimplestOT.h>
#include "../smallSetVoleFast.h"
#include "../field25519/fe25519.h"
#include "../voleUtils.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"

void test_speed()
{
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int len = 128;
    int bits = 8;
    int numTrees = 8; // Actually, RegularPprf.h line 37 says this must be a multiple of 8. But I tried it with different numbers and it did not obviously crash or anything.
    int nrTrials = 10;
    double diff = 0;
    int N = 1<<bits;
    auto pprfReceiver = new RegularPprfReceiver<block,block,CTX>();
    auto pprfSender = new RegularPprfSender<block,block,CTX>(N,numTrees);
    pprfReceiver->configure(N,numTrees);

    for (int i = 0; i < nrTrials; ++i)
    {
        std::cout << "Test trial nr " << i << " started." << std::endl;
        std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

        // The code to be run by the receiver.
        std::vector<std::vector<fe25519>> o;
        std::vector<fe25519> h;
        auto recverThread = std::thread([&]()
                                        {
            PRNG prngRec(sysRandomSeed());
            //  -- Compute OTs
            int numOTs = pprfReceiver->baseOtCount();
            std::vector<block> recvOTs(numOTs);
            BitVector recvBits = pprfReceiver->sampleChoiceBits(prngRec); // RandomOT only randomizes the messsages not choice bits. So choose randomly.
            OtReceiver* otrec = new SimplestOT();
            auto ot_proto = otrec->receive(recvBits, recvOTs, prngRec, sockets[0]);
            coproto::sync_wait(macoro::wrap(ot_proto));
                    
            //  -- Compute N-1 out of N OT
            pprfReceiver->setBase(recvOTs);
            Vec a(N * numTrees); // contains first N*k_zkp entries for the ZKP and the other N*k_vole entries are for VOLE+
            std::vector<u64> points(numTrees); 
            pprfReceiver->getPoints(points, FORMAT);
            coproto::sync_wait(macoro::wrap(pprfReceiver->expand(sockets[0], a, FORMAT, false, 1)));
            
            SmallSetVoleReceiver25519 rec(len,bits,numTrees); 
            auto protoRec = rec.receive(o, h,a,0,points,prngRec,sockets[0]);
            macoro::sync_wait(std::move(protoRec)); 
        });
        PRNG prng(sysRandomSeed());
        //  -- Compute OTs
        int numOTs = pprfSender->baseOtCount();
        std::vector<std::array<block, 2>> sendOTs(numOTs);
        OtSender *otsender = new SimplestOT();
        auto ot_proto = otsender->send(sendOTs, prng, sockets[1]); // send is randomOT sendChosen is normal OT
        coproto::sync_wait(macoro::wrap(ot_proto));

        //  -- Compute N-1 out of N OT
        pprfSender->setBase(sendOTs);
        Vec b(N * numTrees); 
        coproto::sync_wait(macoro::wrap(pprfSender->expand(sockets[1], 0, prng.get(), b, FORMAT, false, 1))); // delta is 0 because it's not used because we also set programPuncturedPoint = false, so I guess delta will be ignored.


        SmallSetVoleSender25519 sender(len, bits, numTrees);
        std::vector<std::vector<fe25519>> u;
        std::vector<std::vector<fe25519>> v;
        auto protoSend = sender.send(u, v, b,0,prng, sockets[1]);
        macoro::sync_wait(std::move(protoSend));

        recverThread.join();
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        diff += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    std::cout << "[fast] Time difference avg = " << diff / nrTrials << "[µs]" << std::endl;
}

void test_correctness()
{
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int len = 128;
    int bits = 7;
    int numTrees = 1; // Actually, RegularPprf.h line 37 says this must be a multiple of 8. But I tried it with different numbers and it did not obviously crash or anything.
    int N = 1<<bits;
    auto pprfReceiver = new RegularPprfReceiver<block,block,CTX>();
    auto pprfSender = new RegularPprfSender<block,block,CTX>(N,numTrees);
    pprfReceiver->configure(N,numTrees);
    std::vector<std::vector<fe25519>> o;
    std::vector<fe25519> h;
    auto recverThread = std::thread([&]()
                                    {
        PRNG prngRec(sysRandomSeed());
        //  -- Compute OTs
        int numOTs = pprfReceiver->baseOtCount();
        std::vector<block> recvOTs(numOTs);
        BitVector recvBits = pprfReceiver->sampleChoiceBits(prngRec); // RandomOT only randomizes the messsages not choice bits. So choose randomly.
        OtReceiver* otrec = new SimplestOT();
        auto ot_proto = otrec->receive(recvBits, recvOTs, prngRec, sockets[0]);
        coproto::sync_wait(macoro::wrap(ot_proto));
                
        //  -- Compute N-1 out of N OT
        pprfReceiver->setBase(recvOTs);
        Vec a(N * numTrees); // contains first N*k_zkp entries for the ZKP and the other N*k_vole entries are for VOLE+
        std::vector<u64> points(numTrees); 
        pprfReceiver->getPoints(points, FORMAT);
        coproto::sync_wait(macoro::wrap(pprfReceiver->expand(sockets[0], a, FORMAT, false, 1)));

        SmallSetVoleReceiver25519 rec(len,bits,numTrees); 
        auto protoRec = rec.receive(o, h,a,0,points,prngRec,sockets[0]);
        macoro::sync_wait(std::move(protoRec)); 
    });
    PRNG prng(sysRandomSeed());
    //  -- Compute OTs
    int numOTs = pprfSender->baseOtCount();
    std::vector<std::array<block, 2>> sendOTs(numOTs);
    OtSender *otsender = new SimplestOT();
    auto ot_proto = otsender->send(sendOTs, prng, sockets[1]); // send is randomOT sendChosen is normal OT
    coproto::sync_wait(macoro::wrap(ot_proto));

    //  -- Compute N-1 out of N OT
    pprfSender->setBase(sendOTs);
    Vec b(N * numTrees); 
    coproto::sync_wait(macoro::wrap(pprfSender->expand(sockets[1], 0, prng.get(), b, FORMAT, false, 1))); // delta is 0 because it's not used because we also set programPuncturedPoint = false, so I guess delta will be ignored.


    SmallSetVoleSender25519 sender(len, bits, numTrees);
    std::vector<std::vector<fe25519>> u;
    std::vector<std::vector<fe25519>> v;
    auto protoSend = sender.send(u, v, b,0,prng, sockets[1]);
    macoro::sync_wait(std::move(protoSend));

    recverThread.join();
    // verify that 0 = u + h*v - o
    bool correct = true;
    for (int j = 0; j < numTrees; ++j)
    {
        for (int k = 0; k < len; ++k)
        {
            fe25519 result;
            fe25519_setzero(&result);
            fe25519_mul(&result, &h[j], &v[j][k]);
            fe25519_add(&result, &result, &u[j][k]);
            fe25519_sub(&result, &result, &o[j][k]);
            fe25519_freeze(&result);
            if (!fe25519_iszero(&result))
            {
                std::cerr << "Incorrect at k=" << k << std::endl;
                correct = false;
            }
        }
    }
    std::cout << "Correct: " << std::boolalpha << correct << std::endl;
}

int main()
{

    // test_speed();
    test_correctness();

    return 0;
}