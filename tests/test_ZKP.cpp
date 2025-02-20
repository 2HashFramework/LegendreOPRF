#include <string.h>
#include <stdio.h>
#include <numeric>

#include <libOTe/config.h>

#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"

#include "../MockSmallSetVole.h"
#include "../VolePlus.h"
#include "../LegOPRF_ZKProof.h"
#include "../field25519/fe25519.h"
#include <gmpxx.h>
#include <unistd.h>

using namespace osuCrypto;
using namespace std;

int main()
{
    // Test legendre symbol stuff

    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    auto sockets = coproto::LocalAsyncSocket::makePair();
    int numVole = 2;

    int leval = 128;
    int lcom = 561;
    int small_set_bits = 8;
    int statistical_security_bits = 80;
    int N = 1 << small_set_bits;

    fe25519 K, ru, rv, cu, cv;
    std::vector<fe25519> a(leval), a_squared(leval), v(leval), u(leval),  gamma(leval);
    std::vector<fe25519> s(lcom);
    std::vector<fe25519> offsets(leval+lcom);
    std::vector<unsigned char> e(lcom);

    PRNG prng(sysRandomSeed());

    bool all_correct = true;

    for(int repeat = 0; repeat<10; repeat++){
TIC
        // generate a valid witness and statement
        random_fe25519(&K, prng);
        random_fe25519(&ru, prng);
        random_fe25519(&rv, prng);

        for (size_t i = 0; i < leval; i++)
        {
            random_fe25519(&a[i], prng);
            random_fe25519(&gamma[i], prng);
            random_fe25519(&offsets[i], prng);
            a_squared[i] = a[i] * a[i];
        }
TOC(sample a gamma and offsets)
        for (size_t i = 0; i < lcom; i++)
        {
            random_fe25519(&offsets[leval + i], prng);
            fe25519 K_plus_offset = K + offsets[leval + i];
            e[i] = K_plus_offset.legendre_symbol_with_s(s[i]);
        }
TOC(compute e and s)
        v[0] = a_squared[0];
        u[0] = (K + offsets[0]) * v[0];
        for (size_t i = 1; i < leval; i++)
        {
            v[i] = a_squared[i] * a_squared[i-1];
            u[i] = (K + offsets[i]) * v[i];
        }

        cu = ru + dot_product(gamma,u);
        cv = rv + dot_product(gamma,v);
        cu.reduce_add_sub();
        cv.reduce_add_sub();
TOC(compute u v cu cv)
        auto proverThread = std::thread([&]()
                                        {
            LegOPRF_ZKProver P(leval, lcom, small_set_bits, statistical_security_bits);
            PRNG prover_prng(sysRandomSeed());
            auto SSVSender = new SmallSetVoleSender25519(P.vole_len, small_set_bits, P.k);
            auto pprfSender = new RegularPprfSender<block,block,CTX>(N,P.k);
            auto ot_sender = new SimplestOT();
            

            std::vector<std::vector<fe25519>> ui_zkp;
            std::vector<std::vector<fe25519>> vi_zkp;
            //  -- Compute OTs
            int numOTs = pprfSender->baseOtCount();
            std::vector<std::array<block, 2>> sendOTs(numOTs);
            auto ot_proto = ot_sender->send(sendOTs, prng, sockets[0]); // send is randomOT sendChosen is normal OT
            coproto::sync_wait(macoro::wrap(ot_proto));


            //  -- Compute N-1 out of N OT
            pprfSender->setBase(sendOTs);
            Vec b(N * P.k); 
            coproto::sync_wait(macoro::wrap(pprfSender->expand(sockets[0], 0, prng.get(), b, FORMAT, false, 1)));
            std::vector<std::vector<fe25519>> ui;
            std::vector<std::vector<fe25519>> vi;


            auto ssv_proto = SSVSender->send(ui, vi,b,0, prng, sockets[0]);
            auto r = coproto::sync_wait(macoro::wrap(ssv_proto));
            auto proto = P.commit_to_witness(K, a, s, ru, rv, ui,vi, prover_prng, sockets[0]);
            coproto::sync_wait(proto);

            proto = P.prove(gamma, offsets, prover_prng, sockets[0]);
            coproto::sync_wait(proto);

        });

        LegOPRF_ZKVerifier V(leval, lcom, small_set_bits, statistical_security_bits);
        std::vector<std::vector<fe25519>> oi;
        std::vector<fe25519> hi;
        auto pprfReceiver = new RegularPprfReceiver<block,block,CTX>();
        auto ot_receiver = new SimplestOT();
        pprfReceiver->configure(N,V.k);
        //  -- Compute OTs
        int numOTs = pprfReceiver->baseOtCount();
        std::vector<block> recvOTs(numOTs);
        BitVector recvBits = pprfReceiver->sampleChoiceBits(prng); // RandomOT only randomizes the messsages not choice bits. So choose randomly.
        auto ot_proto = ot_receiver->receive(recvBits, recvOTs, prng, sockets[1]);
        coproto::sync_wait(macoro::wrap(ot_proto));
                
        //  -- Compute N-1 out of N OT
        pprfReceiver->setBase(recvOTs);
        Vec a(N * V.k); // contains first N*k_zkp entries for the ZKP and the other N*k_vole entries are for VOLE+
        std::vector<u64> points(V.k); 
        pprfReceiver->getPoints(points, FORMAT);
        coproto::sync_wait(macoro::wrap(pprfReceiver->expand(sockets[1], a, FORMAT, false, 1)));
        // run the small set VOLE protocol
        SmallSetVoleReceiver25519* SSVReceiver = new SmallSetVoleReceiver25519(V.vole_len, small_set_bits, V.k);
        auto ssv_proto = SSVReceiver->receive(oi, hi,a,0,points, prng, sockets[1]);
        auto r = coproto::sync_wait(macoro::wrap(ssv_proto));


        bool good, correct;
        auto proto = V.commit_to_witness(good,oi,hi,prng, sockets[1]);
        coproto::sync_wait(proto);

        if(!good){
            all_correct = false;
        }
        
        proto = V.verify(correct, gamma, e, cu, cv, offsets, prng, sockets[1]);
        coproto::sync_wait(proto);

        proverThread.join();
TOC(total ZKP time)
        all_correct &= correct; 
        std::cout << "success: " << std::boolalpha << (correct && good) << std::endl;
    }
    std::cout << "Correct: " << std::boolalpha << all_correct << std::endl;
}