#ifndef LEGOPRF_ZK_PROOF
#define LEGOPRF_ZK_PROOF

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

using namespace osuCrypto;

// arithmetic for low-degree polynomials with coefficients in fe25519.

template<long unsigned int D> 
struct poly {
    std::array<fe25519,D+1> coefs;
};

template<long unsigned int D>
void reduce_poly(poly<D> &poly){
    for (size_t i = 0; i <= D; i++)
    {
        poly.coefs[i].reduce_add_sub();
        poly.coefs[i].freeze();
    }
}

template<long unsigned int D>
void set_zero_poly(poly<D> &poly){
    for (size_t i = 0; i <= D; i++)
    {
        poly.coefs[i].setzero();
    }
}

template<long unsigned int D1, long unsigned int D2>
void operator += (poly<D1> &lhs, const poly<D2> &rhs){
    for (size_t i = 0; i <= D2; i++)
    {
        lhs.coefs[i] += rhs.coefs[i];
    }
}

template<long unsigned int D1, long unsigned int D2>
void operator -= (poly<D1> &lhs, const poly<D2> &rhs){
    for (size_t i = 0; i <= D2; i++)
    {
        lhs.coefs[i] -= rhs.coefs[i];
    }
}

template<long unsigned int D1, long unsigned int D2>
poly<D1> shift_up (const poly<D2> &in){
    poly<D1> out;
    for (size_t i = 0; i < D1 - D2; i++)
    {
        out.coefs[i].setzero();
    }
    
    for (size_t i = 0; i <= D2; i++)
    {
        out.coefs[i + D1 - D2] = in.coefs[i];
    }
    return out;
}

template<long unsigned int D>
poly<D> operator + (const poly<D> &lhs, const poly<D> &rhs){
    poly<D> out;
    for (size_t i = 0; i <= D; i++)
    {
        out.coefs[i] = lhs.coefs[i] + rhs.coefs[i];
    }
    return out;
}

template<long unsigned int D1, long unsigned int D2>
poly<D1 + D2> operator * (const poly<D1> &lhs, const poly<D2> &rhs){
    poly<D1 + D2> out;
    for (size_t i = 0; i <= D1 + D2; i++)
    {
        fe25519_setzero(&out.coefs[i]);
    }
    
    for (size_t i = 0; i <= D1; i++)
    {
        for (size_t j = 0; j <= D2; j++)
        {
            out.coefs[i+j] += lhs.coefs[i]*rhs.coefs[j];
        }
    }

    reduce_poly(out);
    return out;
}

// position of things in the witness vector
#define K_pos 0
#define a_pos 1
#define s_pos (a_pos+leval)
#define ru_pos (s_pos + lcom)
#define rv_pos (ru_pos + 1) 
#define a_inv_pos (rv_pos + 1) 
#define mask_pos (a_inv_pos + 1) 
#define check_pos (mask_pos + 4) 

class LegOPRF_ZKProver
{
public:
    int leval;
    int lcom;
    int small_set_bits;
    int statistical_security_bits;
    int k;
    int vole_len;
    std::vector<poly<1>> state;

    LegOPRF_ZKProver(int leval, int lcom, int small_set_bits, int statistical_security_bits) : leval(leval),
                                                                          lcom(lcom),
                                                                          small_set_bits(small_set_bits),
                                                                          statistical_security_bits(statistical_security_bits)
    {
        k = (statistical_security_bits + small_set_bits - 1)/ small_set_bits;
        vole_len = 1 + leval + lcom + 3 + 5;
    };

    task<> commit_to_witness(fe25519 &K, std::vector<fe25519> &a, std::vector<fe25519> &s, fe25519 &ru, fe25519 &rv, 
        std::vector<std::vector<fe25519>>& ui, std::vector<std::vector<fe25519>>& vi, PRNG &prng, Socket &chl){
//TIC
        // initialize constant terms of state
        state.resize(vole_len);
        for (size_t i = 0; i < vole_len; i++)
        {
            state[i].coefs[0].setzero();
        }

        // write witness to degree-1 coefficients of state
        state[K_pos].coefs[1] = K;
        state[ru_pos].coefs[1] = ru;
        state[rv_pos].coefs[1] = rv;
        for (size_t i = 0; i < leval; i++)
        {
            state[a_pos + i].coefs[1] = a[i];
        }
        for (size_t i = 0; i < lcom; i++)
        {
            state[s_pos + i].coefs[1] = s[i];
        }
        for (size_t i = 0; i < 5; i++)
        {
            random_fe25519(&state[mask_pos + i].coefs[1], prng);
        }
        // add inverse of last entry of a to witness
        fe25519_invert(&(state[a_inv_pos].coefs[1]), &a[leval-1]); 

        
        // TODO: we can save leval+7 field elements worth of communication (~= 4.3 KB) 
        // by derandomizing  a, ru, rc, and mask to v_0 instead of to some randomly chosen value 

        std::vector<unsigned char> buffer(k*vole_len*PRIME_BYTES);
        for (size_t i = 0; i < k; i++)
        {
            fe25519 multiplier;
            multiplier.setzero();
            multiplier.v[(i*small_set_bits)/8] = (1 << ((i*small_set_bits) % 8));

            for (size_t j = 0; j < vole_len; j++)
            {
                // compute derandomization to send to the verifier
                fe25519 temp = state[j].coefs[1] - vi[i][j];
                temp.reduce_add_sub();
                temp.freeze();
                temp.pack(buffer.data() + (i*vole_len + j)*PRIME_BYTES);

                // combine ui into constant term of state
                state[j].coefs[0] += multiplier * ui[i][j];
            }
        }

        co_await chl.send(buffer);

        block seed;
        co_await chl.recv(seed);
        PRNG CheckPrng(seed);
        
        // do consistency check 
        std::vector<fe25519> check_gamma(vole_len-1);
        generateF25519VectorFromSeed(check_gamma, seed);

        buffer.resize((k+1)*PRIME_BYTES);

        // compute cv
        fe25519 cv = state[check_pos].coefs[1];
        for (size_t i = 0; i < vole_len-1; i++)
        {
            cv += check_gamma[i]*state[i].coefs[1];
        }
        cv.reduce_add_sub();
        cv.freeze();
        cv.pack(buffer.data());

        // compute cu_i
        for (size_t i = 0; i < k; i++)
        {
            fe25519 cu_i = (ui[i][check_pos] + dot_product(ui[i],check_gamma));
            cu_i.reduce_add_sub();
            cu_i.freeze();
            cu_i.pack(buffer.data() + (i+1)*PRIME_BYTES);
        }
        
        // send cv and cu_i
        co_await chl.send(buffer);

        co_return;
    }

    task<> prove(const std::vector<fe25519> &gamma, const std::vector<fe25519> &offsets, PRNG &prng, Socket &chl){

        // the proof is going to check a random linear combination of the polynomials
        // receive seed to expand linear combination from
        block seed;
        co_await chl.recv(seed);
        PRNG LinCombPrng(seed);

        // commitments to a squared are quadratic polynomials
        std::vector<poly<2>> a_squared(leval); 

        for (size_t i = 0; i < leval; i++)
        {
            a_squared[i] = state[a_pos + i] * state[a_pos + i];
        }

        // first entry
        poly<0> gamma_i;
        gamma_i.coefs[0] = gamma[0];
        poly<1> K_plus_offset = state[K_pos];
        K_plus_offset.coefs[1] += offsets[0];

        poly<4> check_polynomial_v = shift_up<4,2>(gamma_i * a_squared[0]);
        poly<5> check_polynomial_u = check_polynomial_v * K_plus_offset; 
        // remaining entries
        for (size_t i = 1; i < leval; i++)
        {
            gamma_i.coefs[0] = gamma[i];
            K_plus_offset = state[K_pos];
            K_plus_offset.coefs[1] += offsets[i];

            auto temp = gamma_i * a_squared[i] * a_squared[i-1]; 
            check_polynomial_v += temp;
            check_polynomial_u += temp * K_plus_offset; 
        }

        check_polynomial_u += shift_up<5,1>(state[ru_pos]);
        check_polynomial_v += shift_up<4,1>(state[rv_pos]);


        reduce_poly(check_polynomial_u);
        reduce_poly(check_polynomial_v);

        poly<5> check_poly = check_polynomial_u;

        poly<0> scalar;
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += shift_up<5,4>(scalar*check_polynomial_v);

        // (K+l_i)*s_i^2 = E(e) checks
        poly<3> check_poly_ei;
        for (size_t i = 0; i < lcom; i++)
        {
            poly<1> K_plus_offset = state[K_pos];
            poly<0> E;
            set_zero_poly(E);
            K_plus_offset.coefs[1] += offsets[leval + i];

            check_poly_ei = K_plus_offset * state[s_pos+i] * state[s_pos+i];

            random_fe25519(&scalar.coefs[0], LinCombPrng);
            check_poly += shift_up<5,3>(scalar*check_poly_ei);
        }

        // the a_{leval-1} != 0 check
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        poly<2> a_check_poly = state[a_pos + leval - 1] * state[a_inv_pos];
        check_poly += shift_up<5,2>(scalar * a_check_poly);

        // mask the polynomial to make the proof Zero-Knowledge
        check_poly += state[mask_pos];
        check_poly += shift_up<2,1>(state[mask_pos+1]);
        check_poly += shift_up<3,1>(state[mask_pos+2]);
        check_poly += shift_up<4,1>(state[mask_pos+3]);

        reduce_poly(check_poly);

        // send check polynomial 
        std::vector<unsigned char> buffer(5*PRIME_BYTES);
        for (size_t i = 0; i < 5; i++)
        {
            check_poly.coefs[i].pack(buffer.data() + i*PRIME_BYTES);
        }

        co_await chl.send(buffer);

    }
};


class LegOPRF_ZKVerifier
{
public:
    int leval;
    int lcom;
    int small_set_bits;
    int statistical_security_bits;
    int k;
    int vole_len;
    std::vector<fe25519> state;
    fe25519 Delta;

    LegOPRF_ZKVerifier(int leval, int lcom, int small_set_bits, int statistical_security_bits) : leval(leval),
                                                                          lcom(lcom),
                                                                          small_set_bits(small_set_bits),
                                                                          statistical_security_bits(statistical_security_bits)
    {
        k = (statistical_security_bits + small_set_bits - 1)/ small_set_bits;
        vole_len = 1 + leval + lcom + 3 + 5;
    };


    task<> commit_to_witness(bool& good, std::vector<std::vector<fe25519>>& oi, std::vector<fe25519>& hi,PRNG &prng, Socket &chl){
        good = true;


        // receive derandomizations and update o_i
        std::vector<unsigned char> buffer(k*vole_len*PRIME_BYTES);
        co_await chl.recv(buffer);

        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < vole_len; j++)
            {
                fe25519 read;
                read.unpack(buffer.data() + (i*vole_len + j)*PRIME_BYTES);
                oi[i][j] += hi[i]*read;
            }
        }

        // combine small set VOLES
        state.resize(vole_len);
        for (size_t i = 0; i < vole_len; i++)
        {
            state[i].setzero();
        }
        Delta.setzero();

        for (size_t i = 0; i < k; i++)
        {
            fe25519 multiplier;
            multiplier.setzero();
            multiplier.v[(i*small_set_bits)/8] = (1 << ((i*small_set_bits) % 8));
            Delta += multiplier*hi[i];
            for (size_t j = 0; j < vole_len; j++)
            {
                state[j] += multiplier * oi[i][j];
            }
        }

        Delta.reduce_add_sub();
        for (size_t i = 0; i < vole_len; i++)
        {
            state[i].reduce_add_sub();
        }

        // do consistency check 
        block seed = prng.get();
        co_await chl.send(seed);
        PRNG CheckPrng(seed);

        std::vector<fe25519> check_gamma(vole_len-1);
        generateF25519VectorFromSeed(check_gamma, seed);

        buffer.resize((k+1)*PRIME_BYTES);
        co_await chl.recv(buffer);

        fe25519 cv;
        cv.unpack(buffer.data());

        for (size_t i = 0; i < k; i++)
        {
            fe25519 check;
            check.unpack(buffer.data() + (1+i)*PRIME_BYTES);
            check += hi[i]*cv;
            check.reduce_add_sub();
            check.neg();
            check += oi[i][check_pos] + dot_product(oi[i],check_gamma);
            check.reduce_add_sub();
            check.freeze();
            if( !check.iszero() ){
                good = false;
                co_return;
            }
        }
    }

    task<> verify(bool &valid, const std::vector<fe25519> &gamma, const std::vector<unsigned char> &e, const fe25519 &cu, const fe25519 &cv, const std::vector<fe25519> &offsets,
        PRNG &prng, Socket &chl){
        // the proof is going to check a random linear combination of the polynomials
        // send seed to expand linear combination from
        block seed = prng.get();
        co_await chl.send(seed);
        PRNG LinCombPrng(seed);

        // we could avoid computing this stuff, but probably not worth bothering about it
        fe25519 Delta_two = Delta*Delta;
        fe25519 Delta_three = Delta*Delta_two;
        fe25519 Delta_four = Delta_two*Delta_two;
        fe25519 Delta_five = Delta_two*Delta_three;

        std::vector<fe25519> a_squared(leval); 
        for (size_t i = 0; i < leval; i++)
        {
            a_squared[i] = state[a_pos + i] * state[a_pos + i];
        }

        fe25519 K_plus_offset = state[K_pos] + Delta*offsets[0]; 
        fe25519 v_check = gamma[0] * a_squared[0] * Delta_two;
        fe25519 u_check = v_check * K_plus_offset; 

        for (size_t i = 1; i < leval; i++)
        {
            K_plus_offset = state[K_pos] + Delta*offsets[i];
            fe25519 temp = gamma[i] * a_squared[i] * a_squared[i-1]; 
            v_check += temp;
            u_check += temp * K_plus_offset; 
        }
        
        u_check += Delta_four * state[ru_pos];
        v_check += Delta_three * state[rv_pos];
        u_check -= Delta_five * cu; 
        v_check -= Delta_four * cv;

        fe25519 check = u_check;

        fe25519 scalar;
        random_fe25519(&scalar, LinCombPrng);
        check += scalar*Delta*v_check;

        // (K+l_i)*s_i^2 = E(e) checks
        fe25519 check_ei;
        for (size_t i = 0; i < lcom; i++)
        {
            fe25519 K_plus_offset = state[K_pos] + (Delta*offsets[leval + i]);

            check_ei = K_plus_offset * state[s_pos+i] * state[s_pos+i];
            // TODO make this constant time?
            if(e[i] == 1){
                // E = 1
                check_ei -= Delta_three;
            }
            else if (e[i] == 255){
                // E = 2
                check_ei -= Delta_three;
                check_ei -= Delta_three;
            }
            else if (e[i] == 0){
                // E = 0
            }
            else{
                std::cout << "e vector does not contain legendre symbols (0,1,or -1 = 255). Abort prover." << std::endl;
                co_return; 
            }

            random_fe25519(&scalar, LinCombPrng);
            check += Delta_two*scalar*check_ei;
        }

        // a_{leval-1} != 0 check
        random_fe25519(&scalar, LinCombPrng);
        fe25519 a_check = (state[a_pos + leval - 1] * state[a_inv_pos]) - Delta_two;
        check += Delta_three * scalar * a_check;

        // add mask for ZK
        check += state[mask_pos];
        check += Delta*state[mask_pos+1];
        check += Delta_two*state[mask_pos+2];
        check += Delta_three*state[mask_pos+3];

        // receive and evaluate check polynomial
        std::vector<unsigned char> buffer(5*PRIME_BYTES);
        co_await chl.recv(buffer);

        poly<4> check_poly;
        fe25519 eval;
        eval.unpack(buffer.data() + 4*PRIME_BYTES);
        for (int i = 3; i >= 0; i--)
        {
            fe25519 read;
            read.unpack(buffer.data() + i*PRIME_BYTES);
            eval = Delta*eval + read;
        }

        check.reduce_add_sub();
        check.freeze();
        eval.reduce_add_sub();
        eval.freeze();

        // check if evaluation is correct
        eval -= check;
        eval.reduce_add_sub();
        eval.freeze();
        valid = eval.iszero();
    }
};

#endif
