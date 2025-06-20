#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
#include <string>
#include <stdint.h>
#include "uint256.h"

/**
 * Lightweight bignum class that provides the minimal API used across the
 * codebase.  It wraps boost::multiprecision::cpp_int to replace the original
 * OpenSSL based CBigNum class.
 */
class CBigNum {
private:
    boost::multiprecision::cpp_int bn;

public:
    CBigNum() : bn(0) {}
    CBigNum(const CBigNum& b) : bn(b.bn) {}
    CBigNum(const boost::multiprecision::cpp_int& v) : bn(v) {}

    template <typename Int,
              typename = typename std::enable_if<std::is_integral<Int>::value>::type>
    CBigNum(Int v) : bn(v) {}

    explicit CBigNum(const std::vector<unsigned char>& vch) { setvch(vch); }

    CBigNum& operator=(const CBigNum& b) { bn = b.bn; return *this; }

    operator boost::multiprecision::cpp_int&() { return bn; }
    operator const boost::multiprecision::cpp_int&() const { return bn; }

    // Legacy API
    CBigNum& SetCompact(unsigned int nCompact);
    unsigned int GetCompact() const;

    uint256 getuint256() const;
    std::vector<unsigned char> getvch() const;
    int getint() const { return bn.convert_to<int>(); }
    unsigned long getulong() const { return bn.convert_to<unsigned long>(); }

    CBigNum& setvch(const std::vector<unsigned char>& vch);
    CBigNum& setint64(int64_t n) { bn = n; return *this; }
    CBigNum& setulong(unsigned long n) { bn = n; return *this; }

    std::string ToString() const { return bn.convert_to<std::string>(); }
};

inline CBigNum& CBigNum::SetCompact(unsigned int nCompact)
{
    unsigned int nSize = nCompact >> 24;
    unsigned int nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        bn = nWord;
    } else {
        bn = nWord;
        bn <<= 8 * (nSize - 3);
    }
    if (nCompact & 0x00800000)
        bn = -bn;
    return *this;
}

inline unsigned int CBigNum::GetCompact() const
{
    boost::multiprecision::cpp_int tmp = bn;
    bool negative = tmp < 0;
    if (negative) tmp = -tmp;
    int nSize = (tmp == 0) ? 0 : (boost::multiprecision::msb(tmp) + 8) / 8;
    unsigned int nCompact = 0;
    if (nSize <= 3) {
        nCompact = tmp.convert_to<unsigned int>() << 8 * (3 - nSize);
    } else {
        tmp >>= 8 * (nSize - 3);
        nCompact = tmp.convert_to<unsigned int>();
    }
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= nSize << 24;
    if (negative) nCompact |= 0x00800000;
    return nCompact;
}

inline uint256 CBigNum::getuint256() const
{
    boost::multiprecision::cpp_int tmp = bn;
    if (tmp < 0) tmp = -tmp;
    uint256 result;
    unsigned char* p = result.begin();
    for (unsigned int i = 0; i < 32; ++i) {
        p[i] = static_cast<unsigned char>(tmp & 0xff);
        if (tmp != 0) tmp >>= 8;
    }
    return result;
}

inline std::vector<unsigned char> CBigNum::getvch() const
{
    boost::multiprecision::cpp_int tmp = bn;
    std::vector<unsigned char> vch;
    bool negative = tmp < 0;
    if (negative) tmp = -tmp;
    while (tmp != 0) {
        vch.push_back(static_cast<unsigned char>(tmp & 0xff));
        tmp >>= 8;
    }
    if (vch.empty()) vch.push_back(0);
    if (vch.back() & 0x80)
        vch.push_back(negative ? 0x80 : 0);
    else if (negative)
        vch.back() |= 0x80;
    return vch;
}

inline CBigNum& CBigNum::setvch(const std::vector<unsigned char>& vch)
{
    bn = 0;
    if (vch.empty())
        return *this;
    std::vector<unsigned char> tmp(vch);
    bool negative = (tmp.back() & 0x80) != 0;
    if (negative)
        tmp.back() &= 0x7f;
    for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) {
        bn <<= 8;
        bn += *it;
    }
    if (negative)
        bn = -bn;
    return *this;
}
#endif // BITCOIN_BIGNUM_H
