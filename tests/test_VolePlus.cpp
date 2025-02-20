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

    int len = 3;
    int small_set_bits = 8;
    int statistical_security_bits = 80;
    int N = 1 << small_set_bits; // SmallSetSize of the smalSetVole
    VolePlus VP(len, small_set_bits, statistical_security_bits);
    auto pprfReceiver = new RegularPprfReceiver<block,block,CTX>();
    auto pprfSender = new RegularPprfSender<block,block,CTX>(N,VP.k+1);
    pprfReceiver->configure(N,VP.k+1);
    auto ot_sender = new SimplestOT();
    auto ot_receiver = new SimplestOT();


    // Prepare Small Set Vole
    SmallSetVoleSender25519 *SSVSender;
    SmallSetVoleReceiver25519 *SSVReceiver;

        
    cout << "\n\n Test Vole+\n";
    SSVSender = new SmallSetVoleSender25519(VP.len + 1, VP.small_set_bits, VP.k);
    SSVReceiver = new SmallSetVoleReceiver25519(VP.len + 1, VP.small_set_bits, VP.k);

    std::vector<fe25519> o(len);
    fe25519 h;
    fe25519 cu, cv;

    std::vector<fe25519> gammaRec(len);

    auto recverThread = std::thread([&]()
                                    {
        PRNG prng(block(0xBADF00D));

        //  -- Compute OTs
        int numOTs = pprfReceiver->baseOtCount();
        std::vector<block> recvOTs(numOTs);
        BitVector recvBits = pprfReceiver->sampleChoiceBits(prng); // RandomOT only randomizes the messsages not choice bits. So choose randomly.
        auto ot_proto = ot_receiver->receive(recvBits, recvOTs, prng, sockets[0]);
        coproto::sync_wait(macoro::wrap(ot_proto));
                
        //  -- Compute N-1 out of N OT
        pprfReceiver->setBase(recvOTs);
        Vec a(N * (VP.k+1)); // contains first N*k_zkp entries for the ZKP and the other N*k_vole entries are for VOLE+
        std::vector<u64> points(VP.k+1); 
        pprfReceiver->getPoints(points, FORMAT);
        coproto::sync_wait(macoro::wrap(pprfReceiver->expand(sockets[0], a, FORMAT, false, 1)));


        // -- run the small set VOLE protocol for VOLE+ 
        std::vector<std::vector<fe25519>> oi_vole;
        std::vector<fe25519> hi_vole;
        // a_offset = 1 means one whole PPRF tree, i.e., N elements will be skipped
        auto vole_proto = SSVReceiver->receive(oi_vole, hi_vole,a,1, points, prng, sockets[0]);
        coproto::sync_wait(macoro::wrap(vole_proto)); 


        // choose random input
        random_fe25519(&h, prng);
        auto proto = VP.receive(h, o, gammaRec, cu, cv, oi_vole,hi_vole,prng, sockets[0]);
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
        std::cout  << "Received gamma Rec: \n";
        for (size_t i = 0; i < len; i++)
        {
            std::cout << gammaRec[i] << std::endl;
        } });

    std::vector<fe25519> u(len), v(len), gammaSender(len);
    for (size_t i = 0; i < len; ++i)
    {
        fe25519_setone(&u[i]);
        fe25519_setone(&v[i]);
    }

    fe25519 ru, rv;
    fe25519_setzero(&ru);
    fe25519_setzero(&rv);

    // Send
    PRNG prng(block(0xBADF00E));
    //  -- Compute OTs
    int numOTs = pprfSender->baseOtCount();
    std::vector<std::array<block, 2>> sendOTs(numOTs);
    auto ot_proto = ot_sender->send(sendOTs, prng, sockets[1]); // send is randomOT sendChosen is normal OT
    coproto::sync_wait(macoro::wrap(ot_proto));


    //  -- Compute N-1 out of N OT
    pprfSender->setBase(sendOTs);
    Vec b(N * (VP.k+1)); 
    coproto::sync_wait(macoro::wrap(pprfSender->expand(sockets[1], 0, prng.get(), b, FORMAT, false, 1))); // delta is 0 because it's not used because we also set programPuncturedPoint = false, so I guess delta will be ignored.

    // -- run the small set VOLE protocol for VOLE+ 
    std::vector<std::vector<fe25519>> ui_vole;
    std::vector<std::vector<fe25519>> vi_vole;

    auto vole_proto = SSVSender->send(ui_vole,vi_vole,b, 1,prng,sockets[1]);
    coproto::sync_wait(macoro::wrap(vole_proto));

    std::cout << "Started sender" << std::endl;
    auto proto = VP.send(u, v, ru, rv, gammaSender, ui_vole,vi_vole, prng, sockets[1]);


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
    fe25519 tmp;
    for (size_t i = 0; i < len; i++)
    {
        fe25519_mul(&tmp, &h, &v[i]);
        fe25519_add(&tmp, &tmp, &u[i]);
        fe25519_sub(&tmp, &tmp, &o[i]);
        fe25519_freeze(&tmp);
        if (!fe25519_iszero(&tmp))
        {
            // if((o[i] %prime != (u[i]+ h*v[i])%prime)){
            std::cerr << "VOLE+ Correlation wrong at " << i << std::endl;
            correct = false;
        }
    }
    for (size_t i = 0; i < len; ++i)
    {
        fe25519_sub(&tmp, &gammaSender[i], &gammaRec[i]);
        fe25519_freeze(&tmp);
        if (!fe25519_iszero(&tmp))
        {
            correct = false;
            std::cerr << "Mismatching gamma." << std::endl;
        }
    }
    // Check inner products
    tmp = dot_product(gammaRec, u);
    fe25519_add(&tmp, &tmp, &ru);
    fe25519_sub(&tmp, &tmp, &cu);
    fe25519_freeze(&tmp);
    if (!fe25519_iszero(&tmp))
    {
        correct = false;
        std::cerr << "Commitment on u wrong." << std::endl;
    }
    // Check inner products
    tmp = dot_product(gammaRec, v);
    fe25519_add(&tmp, &tmp, &rv);
    fe25519_sub(&tmp, &tmp, &cv);\
    fe25519_freeze(&tmp);
    if (!fe25519_iszero(&tmp))
    {
        std::cerr << "Commitment on v wrong." << std::endl;
        correct = false;
    }

    std::cout << "Correct: " << std::boolalpha << correct << std::endl;
}