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
#include "smallSetVoleFast.h"
#include <string>
#include "voleUtils.h"
#include "VolePlus.h"
#include "LegOPRF_ZKProof.h"
#include <cryptoTools/Crypto/Blake2.h>
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/Base/MasnyRindalKyber.h"

using namespace osuCrypto;

class OPRFLeg
{
public:
    int len_eval;
    int len_com;
    int statistical_security_bits;
    int small_set_bits;
    // Offsets is (l',l)
    std::vector<fe25519> offsets;
    int N;
    int repeats;
    VolePlus *volePlus;
    LegOPRF_ZKProver *prover;
    LegOPRF_ZKVerifier *verifier;
    OtSender *ot_sender;
    OtReceiver *ot_receiver;
    RegularPprfSender<block, block, CTX> *pprfSender;
    RegularPprfReceiver<block, block, CTX> *pprfReceiver;
    SmallSetVoleSender25519* ssVoleSenderZKP;
    SmallSetVoleReceiver25519* ssVoleRecZKP;
    SmallSetVoleSender25519* ssVoleSenderVolePlus;
    SmallSetVoleReceiver25519* ssVoleRecVolePlus;
    IknpOtExtSender *otExtSender;
    IknpOtExtReceiver *otExtRecv;

    OPRFLeg(int len_eval, int len_com, int statistical_security_bits, int small_set_bits) : len_eval(len_eval),
                                                                        len_com(len_com),
                                                                        statistical_security_bits(statistical_security_bits),
                                                                        small_set_bits(small_set_bits)
    {
        volePlus = new VolePlus(len_eval, small_set_bits, statistical_security_bits);

        prover = new LegOPRF_ZKProver(len_eval, len_com,small_set_bits, statistical_security_bits);
        verifier = new LegOPRF_ZKVerifier(len_eval, len_com,small_set_bits, statistical_security_bits);

        ot_sender = new MasnyRindalKyber();
        ot_receiver = new MasnyRindalKyber();
        otExtSender = new IknpOtExtSender();
        otExtRecv = new IknpOtExtReceiver();

        N = 1 << small_set_bits; // SmallSetSize of the smalSetVole
        repeats = prover->k + volePlus->k; // repeat_ZK + repeat Vole+        
        pprfSender = new RegularPprfSender<block,block,CTX>(N,repeats);
        pprfReceiver = new RegularPprfReceiver<block,block,CTX>();
        pprfReceiver->configure(N,repeats);

        ssVoleRecZKP = new SmallSetVoleReceiver25519(verifier->vole_len, small_set_bits, verifier->k);
        ssVoleSenderZKP = new SmallSetVoleSender25519(prover->vole_len, small_set_bits, prover->k);
        ssVoleRecVolePlus = new SmallSetVoleReceiver25519(volePlus->len+1, small_set_bits, volePlus->k);
        ssVoleSenderVolePlus = new SmallSetVoleSender25519(volePlus->len+1, small_set_bits, volePlus->k);
        

        // Compute public parameters l and l' by expanding 0.
        PRNG offset_prng(block(0));
        offsets = std::vector<fe25519>(len_eval + len_com);
        for (size_t i = 0; i < len_com+len_eval; ++i)
        {
            random_fe25519(&offsets[i], offset_prng);
        }
    };

    // Computes a^2 * shift(a)^2 = (a0,a0*a1,a1*a2,... )
    void shift_sq_product(std::vector<fe25519> &v, std::vector<fe25519> &a_square)
    {
        v.resize(len_eval);
        v[0] = a_square[0];
        for (size_t i = 1; i < len_eval; ++i)
        {
            v[i] = a_square[i] * a_square[i - 1];
        }
    }

    // Checks if the client should abort because of an detected e_i = 0 with f(h,-li) != (e,e'). This protects against the server setting si = 0
    bool check_abort_on_e_0(const fe25519 &h, const std::vector<unsigned char> e, const fe25519 li)
    {
        bool abort = true;
        for (size_t i = 0; i < len_com; ++i)
        {
            fe25519 expected_e = offsets[len_eval + i] - li;
            if (e[i] != expected_e.legendre_symbol())
            {
                abort = false;
            }
        }
        for (size_t i = 0; i < len_eval; ++i)
        {
            fe25519 expected_oi = h + offsets[i] - li;
            expected_oi.reduce_add_sub();
            if (e[len_com + i] != expected_oi.legendre_symbol())
            {
                abort = false;
            }
        }
        return abort;
    }

    // User's code. x is the point on which the OPRF will be evaluated. The PRF value will be written to output.
    task<> eval(
        std::vector<char> &x,
        unsigned char *output,
        PRNG &prng,
        Socket &chl)
    {
        // slow hash x into h
        fe25519 h;
        Blake2 hash_one(PRIME_BYTES);
        unsigned char hashed[PRIME_BYTES];
        hash_one.Update(x.data(), x.size());
        hash_one.Final(hashed);
        for (size_t i = 0; i < (1<<16); i++)
        {
            Blake2 hash_repeated(PRIME_BYTES);
            hashed[0] ^= i;
            hashed[1] ^= i/256;
            hash_repeated.Update(hashed, PRIME_BYTES);
            hash_repeated.Final(hashed);
        }
        h.unpack(hashed);

        // Start SFE
        
        //  -- Compute base OTs
        AlignedUnVector<std::array<block, 2>> baseSend(NUM_BASE_OT);
        auto base_ot_proto = ot_sender->send(baseSend, prng, chl);
        coproto::sync_wait(macoro::wrap(base_ot_proto));

        otExtRecv->mHashType = HashType::AesHash; // libOTe does not say what this is. But aes should be good.
        
        // -- Compute OT extensions
        int numOTs = pprfReceiver->baseOtCount();
        otExtRecv->setBaseOts(baseSend);
        std::vector<block> recvOTs(numOTs);
        BitVector recvBits = pprfReceiver->sampleChoiceBits(prng); // RandomOT only randomizes the messsages not choice bits. So choose randomly.
        auto ot_ext_proto = otExtRecv->receive(recvBits ,recvOTs,prng,chl);
        coproto::sync_wait(macoro::wrap(ot_ext_proto));

                
        //  -- Compute N-1 out of N OT
        pprfReceiver->setBase(recvOTs);
        Vec a(N * repeats); // contains first N*k_zkp entries for the ZKP and the other N*k_vole entries are for VOLE+
        std::vector<u64> points(repeats); 
        pprfReceiver->getPoints(points, FORMAT);
        coproto::sync_wait(macoro::wrap(pprfReceiver->expand(chl, a, FORMAT, false, 1)));

        // -- run the small set VOLE protocol for VOLE+ 
        std::vector<std::vector<fe25519>> oi_vole;
        std::vector<fe25519> hi_vole;
        auto vole_proto = ssVoleRecVolePlus->receive(oi_vole, hi_vole,a,verifier->k, points, prng, chl);
        coproto::sync_wait(macoro::wrap(vole_proto)); 

        // -- run the small set VOLE protocol for the ZKP
        std::vector<std::vector<fe25519>> oi_zkp;
        std::vector<fe25519> hi_zkp;
        auto sszkp_proto = ssVoleRecZKP->receive(oi_zkp, hi_zkp,a,0, points, prng, chl);
        coproto::sync_wait(macoro::wrap(sszkp_proto));

        
        // -- Setup ZK Proof
        bool good;
        auto proto_wit = verifier->commit_to_witness(good,oi_zkp,hi_zkp, prng,chl);
        coproto::sync_wait(proto_wit);

        if (!good){
            std::cout << "Abort: The server cheated in the ZK Proof commitment phase." << std::endl;
            co_return;
        } 

        // -- VOLE+
        std::vector<fe25519> o;
        std::vector<fe25519> gamma;
        fe25519 cu, cv;
        auto plus_proto = volePlus->receive(h, o, gamma, cu, cv, oi_vole,hi_vole,prng, chl);
        coproto::sync_wait(macoro::wrap(plus_proto));

        // -- Receive e
        std::vector<unsigned char> buffer(len_com);
        coproto::sync_wait(chl.recv(buffer));
        std::vector<unsigned char> e(len_com);
        for (size_t i = 0; i < len_com; ++i)
        {
            e[i] = buffer[i];
        }

        //  -- ZK Proof
        bool valid;
        auto proto_vfy = verifier->verify(valid,gamma,e,cu,cv,offsets,prng,chl);
        coproto::sync_wait(macoro::wrap(proto_vfy));

        if(!valid){
            std::cout << "Abort: ZK Proof did not verify." << std::endl;
            co_return;
        }
        e.resize(len_com+len_eval+x.size());

        char zero_counter = 0;
        for (size_t i = 0; i < len_eval; ++i)
        {
            if(o[i].iszero()){
                if (zero_counter == 1){
                    std::cout << "Abort: two oi are zero" << std::endl;
                    co_return;
                } else {
                    zero_counter++;
                }
            }
            e[len_com + i] = o[i].legendre_symbol();
        }
        for (size_t i = 0; i < len_com; ++i)
        {
            if (e[i] == 0)
            {
                if (check_abort_on_e_0(h, e, offsets[i]))
                {
                    std::cout << "Abort: si = 0 detected" << std::endl;
                    co_return;
                }
            }
        }
        for (size_t i = 0; i < x.size(); ++i)
        {
            e[len_com+len_eval+i] = x[i];
        }
        // End of SFE. Apply second hash
        Blake2 hash_two(OPRF_OUTPUT_BYTES);
        hash_two.Update(e.data(), x.size() + len_com + len_eval);
        hash_two.Final(output);
        co_return;
    }

    // This is the server's code
    task<> blindedEval(
        fe25519 Key,
        PRNG &prng,
        Socket &chl)
    {
        //  - Start SFE
        std::vector<fe25519> a(len_eval);
        std::vector<fe25519> a_square(len_eval);
        for (size_t i = 0; i < len_eval; ++i)
        {
            random_fe25519(&a[i], prng);
            a_square[i] = a[i]*a[i];
        }
        std::vector<fe25519> v;
        shift_sq_product(v, a_square);
        std::vector<fe25519> u(len_eval);
        for (size_t i = 0; i < len_eval; ++i)
        {
            u[i] = (Key + offsets[i]);
            u[i].reduce_add_sub();
            u[i] *= v[i];
        }
        fe25519 ru;
        fe25519 rv;
        random_fe25519(&ru, prng);
        random_fe25519(&rv, prng);

        // -- Compute s and the legendre symbols e
        std::vector<fe25519> s(len_com,fe25519());
        std::vector<unsigned char> e(len_com);
        fe25519 Kli;
        for (size_t i = 0; i < len_com; ++i)
        {
            Kli = Key + offsets[i+len_eval];
            e[i] = Kli.legendre_symbol_with_s(s[i]);
        }

        //  -- Compute base OTs
        AlignedUnVector<block>  baseRecv(NUM_BASE_OT);
        BitVector baseChoice(NUM_BASE_OT);
        baseChoice.randomize(prng);
        auto base_ot_proto = ot_receiver->receive(baseChoice,baseRecv,prng,chl);
        coproto::sync_wait(macoro::wrap(base_ot_proto));

        otExtSender->mHashType = HashType::AesHash;

        // -- Compute OT extensions
        int numOTs = pprfSender->baseOtCount();
        otExtSender->setBaseOts(baseRecv,baseChoice);
        std::vector<std::array<block, 2>> sendOTs(numOTs);
        auto ot_ext_proto = otExtSender->send(sendOTs, prng, chl); // send is randomOT sendChosen is normal OT
        coproto::sync_wait(macoro::wrap(ot_ext_proto));


        //  -- Compute N-1 out of N OT
        pprfSender->setBase(sendOTs);
        Vec b(N * repeats); 
        coproto::sync_wait(macoro::wrap(pprfSender->expand(chl, 0, prng.get(), b, FORMAT, false, 1))); // delta is 0 because it's not used because we also set programPuncturedPoint = false, so I guess delta will be ignored.

        // -- run the small set VOLE protocol for VOLE+ 
        std::vector<std::vector<fe25519>> ui_vole;
        std::vector<std::vector<fe25519>> vi_vole;

        auto vole_proto = ssVoleSenderVolePlus->send(ui_vole,vi_vole,b, prover->k,prng,chl);
        coproto::sync_wait(macoro::wrap(vole_proto));

        // -- run the small set VOLE protocol for the ZKP
        std::vector<std::vector<fe25519>> ui_zkp;
        std::vector<std::vector<fe25519>> vi_zkp;

        auto sszkp_proto = ssVoleSenderZKP->send(ui_zkp,vi_zkp,b,0,prng,chl);
        coproto::sync_wait(macoro::wrap(sszkp_proto)); 

        
        
        // -- Setup ZK Proof
        auto wit_proto = prover->commit_to_witness(Key,a,s,ru,rv,ui_zkp,vi_zkp,prng,chl);
        coproto::sync_wait(macoro::wrap(wit_proto));

        // -- VOLE+
        std::vector<fe25519> gamma;
        auto plus_proto = volePlus->send(u, v, ru, rv, gamma, ui_vole,vi_vole,prng, chl);
        coproto::sync_wait(macoro::wrap(plus_proto));

        // -- Send e
        coproto::sync_wait(chl.send(e));

        auto proto_prove = prover->prove(gamma,offsets,prng,chl);
        coproto::sync_wait(proto_prove);

        co_return;
    }
};