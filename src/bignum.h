#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"
#include "util.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <stdexcept>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <random>

class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

class CBigNum
{
public:
    boost::multiprecision::cpp_int bn;

    CBigNum() : bn(0) {}
    CBigNum(const CBigNum& b) = default;
    CBigNum& operator=(const CBigNum& b) = default;
    CBigNum(CBigNum&&) noexcept = default;
    CBigNum& operator=(CBigNum&&) noexcept = default;

    template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
    CBigNum(T b) : bn(b) {}
    explicit CBigNum(uint256 n) { setuint256(n); }
    explicit CBigNum(const std::vector<unsigned char>& v) { setvch(v); }

    static CBigNum randBignum(const CBigNum& range);
    static CBigNum RandKBitBigum(const uint32_t k);

    unsigned int bitSize() const { return bn == 0 ? 0 : boost::multiprecision::msb(bn) + 1; }

    void setulong(unsigned long n) { bn = n; }
    unsigned long getulong() const { return static_cast<unsigned long>(bn); }
    unsigned int getuint() const { return static_cast<unsigned int>(bn); }
    int getint() const { return static_cast<int>(bn); }

    void setint64(int64_t n) { bn = n; }
    uint64_t getuint64() const { return static_cast<uint64_t>(bn); }
    void setuint64(uint64_t n) { bn = n; }

    void setuint256(uint256 n);
    uint256 getuint256() const;

    void setvch(const std::vector<unsigned char>& v);
    std::vector<unsigned char> getvch() const;

    CBigNum& SetCompact(unsigned int nCompact);
    unsigned int GetCompact() const;

    void SetHex(const std::string& str);
    std::string ToString(int base=10) const;
    std::string GetHex() const { return ToString(16); }

    unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
    { return ::GetSerializeSize(getvch(), nType, nVersion); }

    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
    { ::Serialize(s, getvch(), nType, nVersion); }

    template<typename Stream>
    void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
    { std::vector<unsigned char> v; ::Unserialize(s, v, nType, nVersion); setvch(v); }

    CBigNum pow(const CBigNum& e) const;
    CBigNum pow(const int e) const { return pow(CBigNum(e)); }
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const { return CBigNum((bn * b.bn) % m.bn); }
    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const;
    CBigNum inverse(const CBigNum& m) const;
    static CBigNum generatePrime(const unsigned int numBits, bool safe = false);
    CBigNum gcd(const CBigNum& b) const;
    bool isPrime(int checks=25) const;
    bool isOne() const { return bn == 1; }
    bool operator!() const { return bn == 0; }

    CBigNum& operator+=(const CBigNum& b) { bn += b.bn; return *this; }
    CBigNum& operator-=(const CBigNum& b) { bn -= b.bn; return *this; }
    CBigNum& operator*=(const CBigNum& b) { bn *= b.bn; return *this; }
    CBigNum& operator/=(const CBigNum& b) { bn /= b.bn; return *this; }
    CBigNum& operator%=(const CBigNum& b) { bn %= b.bn; return *this; }
    CBigNum& operator<<=(unsigned int shift) { bn <<= shift; return *this; }
    CBigNum& operator>>=(unsigned int shift) { bn >>= shift; return *this; }
    CBigNum& operator++() { ++bn; return *this; }
    CBigNum operator++(int) { CBigNum r(*this); ++bn; return r; }
    CBigNum& operator--() { --bn; return *this; }
    CBigNum operator--(int) { CBigNum r(*this); --bn; return r; }

    friend CBigNum operator+(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn + b.bn); }
    friend CBigNum operator-(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn - b.bn); }
    friend CBigNum operator-(const CBigNum& a) { return CBigNum(-a.bn); }
    friend CBigNum operator*(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn * b.bn); }
    friend CBigNum operator/(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn / b.bn); }
    friend CBigNum operator%(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn % b.bn); }
    friend CBigNum operator<<(const CBigNum& a, unsigned int shift) { return CBigNum(a.bn << shift); }
    friend CBigNum operator>>(const CBigNum& a, unsigned int shift) { return CBigNum(a.bn >> shift); }
    friend bool operator==(const CBigNum& a, const CBigNum& b) { return a.bn == b.bn; }
    friend bool operator!=(const CBigNum& a, const CBigNum& b) { return a.bn != b.bn; }
    friend bool operator<=(const CBigNum& a, const CBigNum& b) { return a.bn <= b.bn; }
    friend bool operator>=(const CBigNum& a, const CBigNum& b) { return a.bn >= b.bn; }
    friend bool operator<(const CBigNum& a, const CBigNum& b) { return a.bn < b.bn; }
    friend bool operator>(const CBigNum& a, const CBigNum& b) { return a.bn > b.bn; }
};

inline std::ostream& operator<<(std::ostream& strm, const CBigNum& b) { return strm << b.ToString(10); }

using Bignum = CBigNum;

#endif

inline void CBigNum::setuint256(uint256 n)
{
    bn = 0;
    for (int i = uint256::WIDTH - 1; i >= 0; --i) {
        bn <<= 32;
        bn += n.pn[i];
    }
}

inline uint256 CBigNum::getuint256() const
{
    uint256 r;
    boost::multiprecision::cpp_int tmp = bn;
    if (tmp < 0) tmp = -tmp;
    for (int i = 0; i < uint256::WIDTH; ++i) {
        r.pn[i] = static_cast<unsigned int>(tmp & 0xffffffff);
        tmp >>= 32;
    }
    return r;
}

inline void CBigNum::setvch(const std::vector<unsigned char>& v)
{
    if (v.empty()) { bn = 0; return; }
    std::vector<unsigned char> tmp(v.rbegin(), v.rend());
    bool negative = (tmp[0] & 0x80) != 0;
    if (negative) tmp[0] &= 0x7f;
    bn = 0;
    boost::multiprecision::import_bits(bn, tmp.begin(), tmp.end());
    if (negative) bn = -bn;
}

inline std::vector<unsigned char> CBigNum::getvch() const
{
    if (bn == 0) return std::vector<unsigned char>();
    boost::multiprecision::cpp_int tmp = bn;
    bool negative = false;
    if (tmp < 0) { negative = true; tmp = -tmp; }
    std::vector<unsigned char> v;
    boost::multiprecision::export_bits(tmp, std::back_inserter(v), 8);
    if (!v.empty() && (v.back() & 0x80))
        v.push_back(0);
    if (negative)
        v.back() |= 0x80;
    std::reverse(v.begin(), v.end());
    return v;
}

inline CBigNum& CBigNum::SetCompact(unsigned int nCompact)
{
    unsigned int nSize = nCompact >> 24;
    unsigned int nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        bn = nWord >> (8 * (3 - nSize));
    } else {
        bn = boost::multiprecision::cpp_int(nWord);
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
    unsigned int nSize = tmp == 0 ? 0 : (boost::multiprecision::msb(tmp) + 8) / 8;
    unsigned int nCompact;
    if (nSize <= 3) {
        nCompact = static_cast<unsigned int>(tmp & 0xFFFFFFu);
        nCompact <<= 8 * (3 - nSize);
    } else {
        tmp >>= 8 * (nSize - 3);
        nCompact = static_cast<unsigned int>(tmp & 0xFFFFFFu);
    }
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= nSize << 24;
    if (negative)
        nCompact |= 0x00800000;
    return nCompact;
}

inline void CBigNum::SetHex(const std::string& str)
{
    const char* psz = str.c_str();
    while (isspace(*psz)) psz++;
    bool negative = false;
    if (*psz == '-') { negative = true; psz++; }
    if (psz[0] == '0' && tolower(psz[1]) == 'x') psz += 2;
    while (isspace(*psz)) psz++;
    bn = 0;
    while (isxdigit(*psz)) {
        bn <<= 4;
        char c = *psz++;
        int n = (c >= '0' && c <= '9') ? c - '0' :
                (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
        bn += n;
    }
    if (negative)
        bn = -bn;
}

inline std::string CBigNum::ToString(int base) const
{
    if (base == 10)
        return bn.convert_to<std::string>();
    if (base == 16) {
        std::vector<unsigned char> v;
        boost::multiprecision::cpp_int tmp = bn;
        bool negative = false;
        if (tmp < 0) { negative = true; tmp = -tmp; }
        boost::multiprecision::export_bits(tmp, std::back_inserter(v), 8);
        std::string s;
        static const char* hex = "0123456789abcdef";
        for (auto it = v.rbegin(); it != v.rend(); ++it) {
            s.push_back(hex[*it >> 4]);
            s.push_back(hex[*it & 15]);
        }
        if (s.empty()) s = "0";
        if (negative) s.insert(s.begin(), '-');
        return s;
    }
    return "";
}

inline CBigNum CBigNum::pow(const CBigNum& e) const
{
    if (e.bn < 0)
        throw bignum_error("CBigNum::pow : negative exponent");
    CBigNum base = *this;
    CBigNum exp = e;
    CBigNum result = 1;
    while (exp.bn > 0) {
        if ((exp.bn & 1) != 0)
            result.bn *= base.bn;
        base.bn *= base.bn;
        exp.bn >>= 1;
    }
    return result;
}

inline CBigNum CBigNum::pow_mod(const CBigNum& e, const CBigNum& m) const
{
    if (e.bn < 0) {
        CBigNum inv = this->inverse(m);
        return inv.pow_mod(-e, m);
    }
    CBigNum base = *this % m;
    CBigNum exp = e;
    CBigNum result = 1;
    while (exp.bn > 0) {
        if ((exp.bn & 1) != 0)
            result.bn = (result.bn * base.bn) % m.bn;
        base.bn = (base.bn * base.bn) % m.bn;
        exp.bn >>= 1;
    }
    return result;
}

inline CBigNum CBigNum::inverse(const CBigNum& m) const
{
    CBigNum a = *this % m;
    CBigNum b = m;
    CBigNum x0 = 1, x1 = 0;
    while (b.bn != 0) {
        CBigNum q = a / b;
        CBigNum t = a % b; a = b; b = t;
        t = x0 - q * x1; x0 = x1; x1 = t;
    }
    if (a.bn != 1)
        throw bignum_error("CBigNum::inverse : not invertible");
    if (x0.bn < 0) x0.bn += m.bn;
    return x0;
}

inline CBigNum CBigNum::gcd(const CBigNum& b) const
{
    CBigNum a = *this;
    CBigNum c = b;
    while (c.bn != 0) {
        CBigNum t = a % c;
        a = c;
        c = t;
    }
    return a;
}

inline bool CBigNum::isPrime(int checks) const
{
    if (bn <= 1) return false;
    static const unsigned int smallPrimes[] = {2,3,5,7,11,13,17,19,23,0};
    for(unsigned int i=0; smallPrimes[i]; ++i) {
        if (bn == smallPrimes[i]) return true;
        if (bn % smallPrimes[i] == 0) return false;
    }
    CBigNum d = bn - 1;
    unsigned int s = 0;
    while ((d.bn & 1) == 0) { d.bn >>= 1; ++s; }
    for (int i = 0; i < checks; ++i) {
        CBigNum a = randBignum(*this - 2) + 2;
        CBigNum x = a.pow_mod(d, *this);
        if (x == 1 || x == bn - 1) continue;
        bool cont = false;
        for (unsigned int r = 1; r < s; ++r) {
            x = x.pow_mod(2, *this);
            if (x == bn - 1) { cont = true; break; }
        }
        if (!cont) return false;
    }
    return true;
}

inline CBigNum CBigNum::generatePrime(const unsigned int numBits, bool safe)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    while (true) {
        CBigNum candidate = RandKBitBigum(numBits);
        candidate.bn |= (boost::multiprecision::cpp_int(1) << (numBits-1));
        candidate.bn |= 1; // odd
        if (candidate.isPrime() && (!safe || ((candidate - 1)/2).isPrime()))
            return candidate;
    }
}

inline CBigNum CBigNum::randBignum(const CBigNum& range)
{
    if (range.bn <= 0)
        throw bignum_error("CBigNum::randBignum : invalid range");
    CBigNum ret;
    unsigned int bits = range.bitSize();
    do {
        ret = RandKBitBigum(bits);
    } while (ret >= range || ret == 0);
    return ret;
}

inline CBigNum CBigNum::RandKBitBigum(const uint32_t k)
{
    CBigNum ret = 0;
    unsigned int bytes = (k + 7) / 8;
    for (unsigned int i = 0; i < bytes; ++i) {
        ret.bn <<= 8;
        ret.bn += GetRand(256);
    }
    unsigned int extra = bytes * 8 - k;
    if (extra > 0)
        ret.bn >>= extra;
    return ret;
}

#endif
