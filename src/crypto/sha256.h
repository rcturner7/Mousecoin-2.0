#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

class CSHA256
{
private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA256& Reset();
};

class CHash256
{
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    CHash256& Write(const unsigned char* data, size_t len) {
        sha.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset();
        sha.Write(buf, OUTPUT_SIZE).Finalize(hash);
    }
    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

void SHA256Transform(uint32_t state[8], const unsigned char block[64]);

#endif // BITCOIN_CRYPTO_SHA256_H
