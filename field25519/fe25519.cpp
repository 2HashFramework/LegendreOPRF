#include "fe25519.h"

#define WINDOWSIZE 4 /* Should be 1,2, or 4 */
#define WINDOWMASK ((1 << WINDOWSIZE) - 1)

void fe25519_reduce_add_sub(fe25519 *r)
{
    crypto_uint32 t;
    int i, rep;

    for (rep = 0; rep < 4; rep++)
    {
        t = r->v[31] >> 7;
        r->v[31] &= 127;
        t *= 19;
        r->v[0] += t;
        for (i = 0; i < 31; i++)
        {
            t = r->v[i] >> 8;
            r->v[i + 1] += t;
            r->v[i] &= 255;
        }
    }
}

static void reduce_mul(fe25519 *r)
{
    crypto_uint32 t;
    int i, rep;

    for (rep = 0; rep < 2; rep++)
    {
        t = r->v[31] >> 7;
        r->v[31] &= 127;
        t *= 19;
        r->v[0] += t;
        for (i = 0; i < 31; i++)
        {
            t = r->v[i] >> 8;
            r->v[i + 1] += t;
            r->v[i] &= 255;
        }
    }
}

/* reduction modulo 2^255-19 */
void fe25519_freeze(fe25519 *r)
{
    int i;
    unsigned int m = (r->v[31] == 127);
    for (i = 30; i >= 1; i--)
        m *= (r->v[i] == 255);
    m *= (r->v[0] >= 237);

    r->v[31] -= m * 127;
    for (i = 30; i > 0; i--)
        r->v[i] -= m * 255;
    r->v[0] -= m * 237;
}

/*freeze input before calling isone*/
static int isone(const fe25519 *x)
{
    int i;
    int r = (x->v[0] == 1);
    for (i = 1; i < 32; i++)
        r *= (x->v[i] == 0);
    return r;
}

/*freeze input before calling iszero*/
int fe25519_iszero(const fe25519 *x)
{
    int i;
    int r = (x->v[0] == 0);
    for (i = 1; i < 32; i++)
        r *= (x->v[i] == 0);
    return r;
}

int fe25519_issquare(const fe25519 *x)
{
    unsigned char e[32] = {0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}; /* (p-1)/2 */
    fe25519 t;

    fe25519_pow(&t, x, e);
    fe25519_freeze(&t);
    return isone(&t) || fe25519_iszero(&t);
}

void fe25519_unpack(fe25519 *r, const unsigned char x[32])
{
    int i;
    for (i = 0; i < 32; i++)
        r->v[i] = x[i];
    r->v[31] &= 127;
}

/* Assumes input x being reduced mod 2^255 */
void fe25519_pack(unsigned char r[32], const fe25519 *x)
{
    int i;
    for (i = 0; i < 32; i++)
        r[i] = x->v[i];

    /* freeze byte array */
    unsigned int m = (r[31] == 127); /* XXX: some compilers might use branches; fix */
    for (i = 30; i > 1; i--)
        m *= (r[i] == 255);
    m *= (r[0] >= 237);
    r[31] -= m * 127;
    for (i = 30; i > 0; i--)
        r[i] -= m * 255;
    r[0] -= m * 237;
}

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
    unsigned char nb = 1 - b;
    int i;
    for (i = 0; i < 32; i++)
        r->v[i] = nb * r->v[i] + b * x->v[i];
}

unsigned char fe25519_getparity(const fe25519 *x)
{
    fe25519 t;
    int i;
    for (i = 0; i < 32; i++)
        t.v[i] = x->v[i];
    fe25519_freeze(&t);
    return t.v[0] & 1;
}

void fe25519_setone(fe25519 *r)
{
    int i;
    r->v[0] = 1;
    for (i = 1; i < 32; i++)
        r->v[i] = 0;
}

void fe25519_setzero(fe25519 *r)
{
    int i;
    for (i = 0; i < 32; i++)
        r->v[i] = 0;
}

void fe25519_neg(fe25519 *r, const fe25519 *x)
{
    fe25519 t;
    int i;
    for (i = 0; i < 32; i++)
        t.v[i] = x->v[i];
    fe25519_setzero(r);
    fe25519_sub(r, r, &t);
}

void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
    int i;
    for (i = 0; i < 32; i++)
        r->v[i] = x->v[i] + y->v[i];
    fe25519_reduce_add_sub(r);
}

void fe25519_add_lazy(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
    int i;
    for (i = 0; i < 32; i++)
        r->v[i] = x->v[i] + y->v[i];
}

void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
    int i;
    crypto_uint32 t[32];
    t[0] = x->v[0] + 0x1da;
    t[31] = x->v[31] + 0xfe;
    for (i = 1; i < 31; i++)
        t[i] = x->v[i] + 0x1fe;
    for (i = 0; i < 32; i++)
        r->v[i] = t[i] - y->v[i];
    fe25519_reduce_add_sub(r);
}

void fe25519_sub_lazy(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
    int i;
    crypto_uint32 t[32];
    t[0] = x->v[0] + 0x1da;
    t[31] = x->v[31] + 0xfe;
    for (i = 1; i < 31; i++)
        t[i] = x->v[i] + 0x1fe;
    for (i = 0; i < 32; i++)
        r->v[i] = t[i] - y->v[i];
}

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
    int i, j;
    crypto_uint32 t[63];
    for (i = 0; i < 63; i++)
        t[i] = 0;

    for (i = 0; i < 32; i++)
        for (j = 0; j < 32; j++)
            t[i + j] += x->v[i] * y->v[j];

    for (i = 32; i < 63; i++)
        r->v[i - 32] = t[i - 32] + 38 * t[i];
    r->v[31] = t[31]; /* result now in r[0]...r[31] */

    reduce_mul(r);
}

void fe25519_square(fe25519 *r, const fe25519 *x)
{
    int i, j;
    crypto_uint32 t[63];
    for (i = 0; i < 63; i++)
        t[i] = 0;

    for (i = 0; i < 32; i++){
        t[i + i] += x->v[i] * x->v[i];
        for (j = i+1; j < 32; j++){
            t[i + j] += 2 * x->v[i] * x->v[j];
        }
    }

    for (i = 32; i < 63; i++)
        r->v[i - 32] = t[i - 32] + 38 * t[i];
    r->v[31] = t[31]; /* result now in r[0]...r[31] */
    reduce_mul(r);
}

/*XXX: Make constant time! */
void fe25519_pow(fe25519 *r, const fe25519 *x, const unsigned char *e)
{
    
    fe25519 g;
    fe25519_setone(&g);
    int i, j, k;
    fe25519 pre[(1 << WINDOWSIZE)];
    fe25519 t;
    unsigned char w;

    // Precomputation
    fe25519_setone(pre);
    pre[1] = *x;
    for (i = 2; i < (1 << WINDOWSIZE); i += 2)
    {
        fe25519_square(pre + i, pre + i / 2);
        fe25519_mul(pre + i + 1, pre + i, pre + 1);
    }

    // Fixed-window scalar multiplication
    for (i = 32; i > 0; i--)
    {
        for (j = 8 - WINDOWSIZE; j >= 0; j -= WINDOWSIZE)
        {
            for (k = 0; k < WINDOWSIZE; k++)
                fe25519_square(&g, &g);
            // Cache-timing resistant loading of precomputed value:
            w = (e[i - 1] >> j) & WINDOWMASK;
            t = pre[0];
            for (k = 1; k < (1 << WINDOWSIZE); k++)
                fe25519_cmov(&t, &pre[k], k == w);
            fe25519_mul(&g, &g, &t);
        }
    }
    *r = g;
}

/* Return 0 on success, 1 otherwise */
int fe25519_sqrt_vartime(fe25519 *r, const fe25519 *x, unsigned char parity)
{
    /* See HAC, Alg. 3.37 */
    if (!fe25519_issquare(x))
        return -1;
    unsigned char e[32] = {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f};  /* (p-1)/4 */
    unsigned char e2[32] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}; /* (p+3)/8 */
    unsigned char e3[32] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}; /* (p-5)/8 */
    fe25519 p = {{0}};
    fe25519 d;
    int i;
    fe25519_pow(&d, x, e);
    fe25519_freeze(&d);
    if (isone(&d))
        fe25519_pow(r, x, e2);
    else
    {
        for (i = 0; i < 32; i++)
            d.v[i] = 4 * x->v[i];
        fe25519_pow(&d, &d, e3);
        for (i = 0; i < 32; i++)
            r->v[i] = 2 * x->v[i];
        fe25519_mul(r, r, &d);
    }
    fe25519_freeze(r);
    if ((r->v[0] & 1) != (parity & 1))
    {
        fe25519_sub(r, &p, r);
    }
    return 0;
}

void fe25519_invert(fe25519 *r, const fe25519 *x)
{
    fe25519 z2;
    fe25519 z9;
    fe25519 z11;
    fe25519 z2_5_0;
    fe25519 z2_10_0;
    fe25519 z2_20_0;
    fe25519 z2_50_0;
    fe25519 z2_100_0;
    fe25519 t0;
    fe25519 t1;
    int i;

    /* 2 */ fe25519_square(&z2, x);
    /* 4 */ fe25519_square(&t1, &z2);
    /* 8 */ fe25519_square(&t0, &t1);
    /* 9 */ fe25519_mul(&z9, &t0, x);
    /* 11 */ fe25519_mul(&z11, &z9, &z2);
    /* 22 */ fe25519_square(&t0, &z11);
    /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0, &t0, &z9);

    /* 2^6 - 2^1 */ fe25519_square(&t0, &z2_5_0);
    /* 2^7 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^8 - 2^3 */ fe25519_square(&t0, &t1);
    /* 2^9 - 2^4 */ fe25519_square(&t1, &t0);
    /* 2^10 - 2^5 */ fe25519_square(&t0, &t1);
    /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0, &t0, &z2_5_0);

    /* 2^11 - 2^1 */ fe25519_square(&t0, &z2_10_0);
    /* 2^12 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^20 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0, &t1, &z2_10_0);

    /* 2^21 - 2^1 */ fe25519_square(&t0, &z2_20_0);
    /* 2^22 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^40 - 2^20 */ for (i = 2; i < 20; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^40 - 2^0 */ fe25519_mul(&t0, &t1, &z2_20_0);

    /* 2^41 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^42 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^50 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0, &t0, &z2_10_0);

    /* 2^51 - 2^1 */ fe25519_square(&t0, &z2_50_0);
    /* 2^52 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^100 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0, &t1, &z2_50_0);

    /* 2^101 - 2^1 */ fe25519_square(&t1, &z2_100_0);
    /* 2^102 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^200 - 2^100 */ for (i = 2; i < 100; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^200 - 2^0 */ fe25519_mul(&t1, &t0, &z2_100_0);

    /* 2^201 - 2^1 */ fe25519_square(&t0, &t1);
    /* 2^202 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^250 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^250 - 2^0 */ fe25519_mul(&t0, &t1, &z2_50_0);

    /* 2^251 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^252 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^253 - 2^3 */ fe25519_square(&t1, &t0);
    /* 2^254 - 2^4 */ fe25519_square(&t0, &t1);
    /* 2^255 - 2^5 */ fe25519_square(&t1, &t0);
    /* 2^255 - 21 */ fe25519_mul(r, &t1, &z11);
}

fe25519 fe25519::operator+(fe25519 const &op) const
{
    fe25519 tmp;
    fe25519_add_lazy(&tmp, this, &op);
    return tmp;
}

fe25519 fe25519::operator-(fe25519 const &op) const
{
    fe25519 tmp;
    fe25519_sub_lazy(&tmp, this, &op);
    return tmp;
}

fe25519 fe25519::operator*(fe25519 const &op) const
{
    fe25519 tmp;
    fe25519_mul(&tmp, this, &op);
    return tmp;
}

fe25519 fe25519::operator/(fe25519 const &op) const{
    fe25519 tmp;
    fe25519_invert(&tmp,&op);
    fe25519_mul(&tmp,this,&tmp);
    return tmp;
}

fe25519 &fe25519::operator+=(fe25519 const &op)
{
    fe25519_add_lazy(this, this, &op);
    return *this;
}

fe25519 &fe25519::operator-=(fe25519 const &op)
{
    fe25519_sub_lazy(this, this, &op);
    return *this;
}

fe25519 &fe25519::operator*=(fe25519 const &op)
{
    fe25519_mul(this, this, &op);
    return *this;
}

bool fe25519::operator==(fe25519 const &op){
    fe25519 tmp = *this - op; 
    tmp.freeze();
    return tmp.iszero();
}

bool fe25519::operator!=(fe25519 const &op){
    return !(*this == op);
}

void fe25519::unpack(const unsigned char x[32])
{
    fe25519_unpack(this, x);
}

void fe25519::pack(unsigned char r[32])
{
    fe25519_pack(r, this);
}

void fe25519::setone()
{
    fe25519_setone(this);
}
void fe25519::setzero()
{
    fe25519_setzero(this);
}
void fe25519::neg()
{
    fe25519_neg(this, this);
}
void fe25519::freeze()
{
    fe25519_freeze(this);
}
int fe25519::iszero()
{
    return fe25519_iszero(this);
}
void fe25519::reduce_add_sub()
{
    fe25519_reduce_add_sub(this);
}

char fe25519::legendre_symbol(){
    fe25519 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1, t;
    int i;

    // constants
    const fe25519 half_to_the_power_e = {{62, 95, 241, 181, 216, 228, 17, 59, 135, 27, 208, 82, 249, 231, 188, 208, 88, 40, 4, 194, 102, 255, 178, 212, 244, 32, 62, 176, 127, 219, 124, 84}};
    const fe25519 primitive_fourth_root = {{61, 95, 241, 181, 216, 228, 17, 59, 135, 27, 208, 82, 249, 231, 188, 208, 88, 40, 4, 194, 102, 255, 178, 212, 244, 32, 62, 176, 127, 219, 124, 84}};
 
    /* 2 */ fe25519_square(&z2, this);
    /* 4 */ fe25519_square(&t1, &z2);
    /* 8 */ fe25519_square(&t0, &t1);
    /* 9 */ fe25519_mul(&z9, &t0, this);
    /* 11 */ fe25519_mul(&z11, &z9, &z2);
    /* 22 */ fe25519_square(&t0, &z11);
    /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0, &t0, &z9);

    /* 2^6 - 2^1 */ fe25519_square(&t0, &z2_5_0);
    /* 2^7 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^8 - 2^3 */ fe25519_square(&t0, &t1);
    /* 2^9 - 2^4 */ fe25519_square(&t1, &t0);
    /* 2^10 - 2^5 */ fe25519_square(&t0, &t1);
    /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0, &t0, &z2_5_0);

    /* 2^11 - 2^1 */ fe25519_square(&t0, &z2_10_0);
    /* 2^12 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^20 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0, &t1, &z2_10_0);

    /* 2^21 - 2^1 */ fe25519_square(&t0, &z2_20_0);
    /* 2^22 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^40 - 2^20 */ for (i = 2; i < 20; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^40 - 2^0 */ fe25519_mul(&t0, &t1, &z2_20_0);

    /* 2^41 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^42 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^50 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0, &t0, &z2_10_0);

    /* 2^51 - 2^1 */ fe25519_square(&t0, &z2_50_0);
    /* 2^52 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^100 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0, &t1, &z2_50_0);

    /* 2^101 - 2^1 */ fe25519_square(&t1, &z2_100_0);
    /* 2^102 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^200 - 2^100 */ for (i = 2; i < 100; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^200 - 2^0 */ fe25519_mul(&t1, &t0, &z2_100_0);

    /* 2^201 - 2^1 */ fe25519_square(&t0, &t1);
    /* 2^202 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^250 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^250 - 2^0 */ fe25519_mul(&t0, &t1, &z2_50_0);

    /* 2^251 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^252 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^253 - 2^3 */ fe25519_square(&t1, &t0);

    t0 = t1 * (*this) * z2; // 2^253 - 5 = (p-1)/4
    fe25519_square(&t, &t0);

    fe25519_freeze(&t);   
    return (t.v[0] == 236) ? -1 : t.v[0];
}

std::ostream &operator<<(std::ostream &os, const fe25519 &e)
{
    for (size_t i = 0; i < 32; ++i)
    {
        os << e.v[i] << " ";
    }
    return os;
}



// outputs the legendre symbol of x (0,1, or 255)
// and outputs s such that x*s^2 = 0,1 or 2 if (x/p) is 0,1 or 255 respectively
char fe25519::legendre_symbol_with_s(fe25519 &s){
    fe25519 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1;
    int i;

    // constants
    const fe25519 half_to_the_power_e = {{62, 95, 241, 181, 216, 228, 17, 59, 135, 27, 208, 82, 249, 231, 188, 208, 88, 40, 4, 194, 102, 255, 178, 212, 244, 32, 62, 176, 127, 219, 124, 84}};
    const fe25519 primitive_fourth_root = {{61, 95, 241, 181, 216, 228, 17, 59, 135, 27, 208, 82, 249, 231, 188, 208, 88, 40, 4, 194, 102, 255, 178, 212, 244, 32, 62, 176, 127, 219, 124, 84}};
 
    /* 2 */ fe25519_square(&z2, this);
    /* 4 */ fe25519_square(&t1, &z2);
    /* 8 */ fe25519_square(&t0, &t1);
    /* 9 */ fe25519_mul(&z9, &t0, this);
    /* 11 */ fe25519_mul(&z11, &z9, &z2);
    /* 22 */ fe25519_square(&t0, &z11);
    /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0, &t0, &z9);

    /* 2^6 - 2^1 */ fe25519_square(&t0, &z2_5_0);
    /* 2^7 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^8 - 2^3 */ fe25519_square(&t0, &t1);
    /* 2^9 - 2^4 */ fe25519_square(&t1, &t0);
    /* 2^10 - 2^5 */ fe25519_square(&t0, &t1);
    /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0, &t0, &z2_5_0);

    /* 2^11 - 2^1 */ fe25519_square(&t0, &z2_10_0);
    /* 2^12 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^20 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0, &t1, &z2_10_0);

    /* 2^21 - 2^1 */ fe25519_square(&t0, &z2_20_0);
    /* 2^22 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^40 - 2^20 */ for (i = 2; i < 20; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^40 - 2^0 */ fe25519_mul(&t0, &t1, &z2_20_0);

    /* 2^41 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^42 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^50 - 2^10 */ for (i = 2; i < 10; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0, &t0, &z2_10_0);

    /* 2^51 - 2^1 */ fe25519_square(&t0, &z2_50_0);
    /* 2^52 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^100 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0, &t1, &z2_50_0);

    /* 2^101 - 2^1 */ fe25519_square(&t1, &z2_100_0);
    /* 2^102 - 2^2 */ fe25519_square(&t0, &t1);
    /* 2^200 - 2^100 */ for (i = 2; i < 100; i += 2)
    {
        fe25519_square(&t1, &t0);
        fe25519_square(&t0, &t1);
    }
    /* 2^200 - 2^0 */ fe25519_mul(&t1, &t0, &z2_100_0);

    /* 2^201 - 2^1 */ fe25519_square(&t0, &t1);
    /* 2^202 - 2^2 */ fe25519_square(&t1, &t0);
    /* 2^250 - 2^50 */ for (i = 2; i < 50; i += 2)
    {
        fe25519_square(&t0, &t1);
        fe25519_square(&t1, &t0);
    }
    /* 2^250 - 2^0 */ fe25519_mul(&t0, &t1, &z2_50_0);

    /* 2^251 - 2^1 */ fe25519_square(&t1, &t0);
    /* 2^252 - 2^2 */ fe25519_square(&t0, &t1);

    s = t0 * (*this); // 2^252 - 3 = (p-5)/8

    fe25519 s_squared;
    fe25519_square(&s_squared, &s);;
    fe25519 root = s_squared * (*this); // fourth root of unity or zero
    fe25519 legendre_symbol = root*root; // -1 or 1
    legendre_symbol.freeze();

    unsigned char legendre = legendre_symbol.v[0];

    legendre |= ((legendre >> 7) & 1) * 255; // set legendre to 255 if top bit is one.

    fe25519 maybe_new_s = s*half_to_the_power_e;
    fe25519 maybe_new_root = root*primitive_fourth_root;

    // constant time conditional move
    fe25519_cmov(&s, &maybe_new_s, legendre == 255);
    fe25519_cmov(&root, &maybe_new_root, legendre == 255);

    root.freeze();

    maybe_new_s = s*primitive_fourth_root;
    fe25519_cmov(&s, &maybe_new_s, root.v[0] != 1);
    s.freeze();
    return legendre;
}