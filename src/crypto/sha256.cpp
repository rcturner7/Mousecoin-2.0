#include "sha256.h"
#include "common.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
    0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
    0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
    0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
    0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
    0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
    0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
    0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
    0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
    0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
    0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
    0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
    0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul
};

#define ROTR(x,n) ((x>>n) | (x<<(32-n)))
#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x)>>3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x)>>10))

void SHA256Transform(uint32_t state[8], const unsigned char block[64])
{
    uint32_t a,b,c,d,e,f,g,h,t1,t2,w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ReadBE32(block + 4*i);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i];
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

CSHA256::CSHA256() { Reset(); }

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    size_t bufsize = bytes % 64;
    bytes += len;
    if (bufsize && bufsize + len >= 64) {
        memcpy(buf + bufsize, data, 64 - bufsize);
        SHA256Transform(s, buf);
        data += 64 - bufsize;
        len -= 64 - bufsize;
        bufsize = 0;
    }
    while (len >= 64) {
        SHA256Transform(s, data);
        data += 64;
        len -= 64;
    }
    if (len) memcpy(buf + bufsize, data, len);
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - bytes) % 64));
    Write(sizedesc, 8);
    for (int i = 0; i < 8; i++) WriteBE32(hash + 4*i, s[i]);
}

CSHA256& CSHA256::Reset()
{
    bytes = 0;
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
    return *this;
}
