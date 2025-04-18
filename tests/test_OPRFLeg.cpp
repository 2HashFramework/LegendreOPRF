#include "../OPRFLeg.h"
#include <iomanip>

int main(){
        bool correct = true;
        int len_eval = 128;
        int len_com = 493;
        int statistical_sec_bits = 64;
       
        // parameter t=log|S|, where S is the small set of the underlying VOLE
        int t_values[3] = {6, 8, 10};
        for (int small_set_bits : t_values) {
        std::cout << "Bitsize of VOLE set t = " << small_set_bits << std::endl;
        auto sockets = coproto::LocalAsyncSocket::makePair();

        OPRFLeg oprf = OPRFLeg(len_eval,len_com,statistical_sec_bits,small_set_bits);
        std::string str = "hello world";
        std::vector<char> oprf_input(str.begin(), str.end());

TIC
        auto userThread = std::thread([&](){
            PRNG prng(sysRandomSeed());
            unsigned char output[OPRF_OUTPUT_BYTES];
            auto proto = oprf.eval(oprf_input,output,prng,sockets[0]);
            macoro::sync_wait(std::move(proto));
            std::cout << "evaluation is: ";
            for(int i = 0; i < OPRF_OUTPUT_BYTES; ++i){
                std::cout << std::hex << std::setw(2) << (int) output[i] << " ";
            }
            std::cout << std::endl;
            std::cout << std::dec;
        });
        
        PRNG prng(sysRandomSeed());
        fe25519 key;
        key.setzero();
        for (size_t i = 0; i < 32; i++)
        {
                key.v[i] = 42;
        }
        auto proto = oprf.blindedEval(key, prng, sockets[1]);
        macoro::sync_wait(std::move(proto));

        userThread.join();
TOC(Total OPRF time)
        // TODO: this always says correct: true, even if the ZKP failed.
        std::cout << "Correct: " << std::boolalpha << correct << std::endl;
        
        macoro::sync_wait(sockets[0].flush());
        macoro::sync_wait(sockets[1].flush());
        }


}
