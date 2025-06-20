#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <stdint.h>
#include <string.h>

static inline uint32_t ReadLE32(const unsigned char* ptr)
{
    return ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16) | ((uint32_t)ptr[3] << 24);
}

static inline uint64_t ReadLE64(const unsigned char* ptr)
{
    return ((uint64_t)ReadLE32(ptr)) | ((uint64_t)ReadLE32(ptr + 4) << 32);
}

static inline void WriteLE32(unsigned char* ptr, uint32_t x)
{
    ptr[0] = x;
    ptr[1] = x >> 8;
    ptr[2] = x >> 16;
    ptr[3] = x >> 24;
}

static inline void WriteLE64(unsigned char* ptr, uint64_t x)
{
    WriteLE32(ptr, x & 0xffffffff);
    WriteLE32(ptr + 4, x >> 32);
}

static inline uint32_t ReadBE32(const unsigned char* ptr)
{
    return ((uint32_t)ptr[3]) | ((uint32_t)ptr[2] << 8) |
           ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[0] << 24);
}

static inline uint64_t ReadBE64(const unsigned char* ptr)
{
    return ((uint64_t)ReadBE32(ptr) << 32) | ReadBE32(ptr + 4);
}

static inline void WriteBE32(unsigned char* ptr, uint32_t x)
{
    ptr[3] = x;
    ptr[2] = x >> 8;
    ptr[1] = x >> 16;
    ptr[0] = x >> 24;
}

static inline void WriteBE64(unsigned char* ptr, uint64_t x)
{
    WriteBE32(ptr, x >> 32);
    WriteBE32(ptr + 4, x & 0xffffffff);
}

#endif // BITCOIN_CRYPTO_COMMON_H
