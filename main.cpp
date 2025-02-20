#include <iostream>

#include <libOTe/config.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/SimplestOT.h>
#include "smallSetVoleGMP.h"
#include "OPRFLeg.h"

using namespace osuCrypto;
using namespace std;


// This file should eventually just take inputs from the cmd, call the OPRF and return the result

int main(){
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    auto sockets = coproto::LocalAsyncSocket::makePair();

    int len = 128;
    int bits = 2;
    int numTrees = 8; // Actually, RegularPprf.h line 37 says this must be a multiple of 8. But I tried it with different numbers and it did not obviously crash or anything.

    // The code to be run by the receiver.
    std::vector<std::vector<mpz_class>> o;
    std::vector<mpz_class> h;
    auto recverThread = std::thread([&]() {
        PRNG prngRec(sysRandomSeed());
        OtReceiver* otrec = new SimplestOT();
        SmallSetVoleReceiver rec(otrec,len,bits,numTrees); 
        auto protoRec = rec.receive(o, h, prngRec,sockets[0]);
        macoro::sync_wait(std::move(protoRec));
    });
    PRNG prng(sysRandomSeed());
    
    OtSender* otsend = new SimplestOT();
    SmallSetVoleSender sender(otsend,len,bits,numTrees);
    std::vector<std::vector<mpz_class>> u;
    std::vector<std::vector<mpz_class>> v;
    auto protoSend = sender.send(u,v,prng,sockets[1]);
    macoro::sync_wait(std::move(protoSend));

    recverThread.join();

    // r.value();
}

