#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
#include <string>
#include <stdexcept>
#include <stdint.h>

#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "cpp_int_utils.h"

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
    CBigNum(const CBigNum& b) : bn(b.bn) {}
    CBigNum& operator=(const CBigNum& b) { bn = b.bn; return *this; }
    CBigNum(CBigNum&& b) noexcept : bn(std::move(b.bn)) {}
    CBigNum& operator=(CBigNum&& b) noexcept { bn = std::move(b.bn); return *this; }

    CBigNum(signed char n) { bn = n; }
    CBigNum(short n) { bn = n; }
    CBigNum(int n) { bn = n; }
    CBigNum(long n) { bn = n; }
    CBigNum(long long n) { bn = n; }
    CBigNum(unsigned char n) { bn = n; }
    CBigNum(unsigned short n) { bn = n; }
    CBigNum(unsigned int n) { bn = n; }
    CBigNum(unsigned long n) { bn = n; }
    CBigNum(unsigned long long n) { bn = n; }
    explicit CBigNum(uint256 n) { setuint256(n); }
    explicit CBigNum(const std::vector<unsigned char>& vch) { setvch(vch); }

    static CBigNum randBignum(const CBigNum& range)
    {
        CBigNum ret;
        do {
            ret = RandKBitBignum(range.bitSize());
        } while (ret >= range || ret == 0);
        return ret;
    }

    static CBigNum RandKBitBignum(const uint32_t k)
    {
        if (k == 0) return CBigNum();
        size_t bytes = (k + 7) / 8;
        std::vector<unsigned char> buf(bytes);
        for (size_t i = 0; i < bytes; ++i)
            buf[i] = (unsigned char)GetRand(256);
        if (k % 8)
            buf[bytes-1] &= ((1 << (k % 8)) - 1);
        return CBigNum(buf);
    }

    int bitSize() const
    {
        if (bn == 0) return 0;
        return boost::multiprecision::msb(bn) + 1;
    }

    void setulong(unsigned long n) { bn = n; }
    unsigned long getulong() const { return static_cast<unsigned long>(bn); }
    unsigned int getuint() const { return static_cast<unsigned int>(bn); }
    int getint() const { return static_cast<int>(bn); }

    void setint64(int64_t n) { bn = n; }
    uint64_t getuint64() const { return static_cast<uint64_t>(bn); }
    void setuint64(uint64_t n) { bn = n; }

    void setuint256(uint256 n)
    {
        bn = 0;
        for (int i = 0; i < 32; ++i)
        {
            bn <<= 8;
            bn += n.begin()[31 - i];
        }
    }

    uint256 getuint256() const
    {
        uint256 n;
        boost::multiprecision::cpp_int tmp = bn;
        if (tmp < 0) tmp = -tmp;
        for (int i = 0; i < 32; ++i)
        {
            n.begin()[i] = static_cast<unsigned char>(tmp & 0xff);
            tmp >>= 8;
        }
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        bn = 0;
        if (vch.empty()) return;
        bool negative = (vch.back() & 0x80) != 0;
        std::vector<unsigned char> tmp(vch);
        if (negative) tmp.back() &= 0x7f;
        for (size_t i = 0; i < tmp.size(); ++i)
        {
            bn <<= 8;
            bn += tmp[tmp.size()-1-i];
        }
        if (negative) bn = -bn;
    }

    std::vector<unsigned char> getvch() const
    {
        std::vector<unsigned char> result;
        boost::multiprecision::cpp_int tmp = bn;
        bool negative = false;
        if (tmp < 0) { negative = true; tmp = -tmp; }
        while (tmp > 0)
        {
            result.push_back(static_cast<unsigned char>(tmp & 0xff));
            tmp >>= 8;
        }
        if (!result.empty())
        {
            if (result.back() & 0x80)
                result.push_back(negative ? 0x80 : 0);
            else if (negative)
                result.back() |= 0x80;
        }
        else if (negative)
            result.push_back(0x80);
        return result;
    }

    CBigNum& SetCompact(unsigned int nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        unsigned int nWord = nCompact & 0x007fffff;
        if (nSize <= 3) {
            nWord >>= 8*(3-nSize);
            bn = nWord;
        } else {
            bn = boost::multiprecision::cpp_int(nWord);
            bn <<= 8*(nSize-3);
        }
        if (nCompact & 0x00800000)
            bn = -bn;
        return *this;
    }

    unsigned int GetCompact() const
    {
        boost::multiprecision::cpp_int tmp = bn;
        bool negative = tmp < 0;
        if (negative) tmp = -tmp;
        int size = (bitSize() + 7)/8;
        boost::multiprecision::cpp_int c = tmp;
        if (size <= 3)
            c <<= 8*(3-size);
        else
            c >>= 8*(size-3);
        unsigned int nCompact = static_cast<unsigned int>(c & 0x007fffff);
        nCompact |= size << 24;
        if (negative)
            nCompact |= 0x00800000;
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        std::string s(str);
        const char* psz = s.c_str();
        while (isspace(*psz)) ++psz;
        bool neg = false;
        if (*psz == '-') { neg = true; ++psz; }
        if (psz[0]=='0' && tolower(psz[1])=='x') psz += 2;
        while (isspace(*psz)) ++psz;
        bn = 0;
        while (isxdigit(*psz))
        {
            bn <<= 4;
            char c = tolower(*psz++);
            int n = (c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10;
            bn += n;
        }
        if (neg) bn = -bn;
    }

    std::string ToString(int nBase=10) const
    {
        if (nBase == 16) return GetHex();
        return bn.convert_to<std::string>();
    }

    std::string GetHex() const
    {
        std::vector<unsigned char> vch = getvch();
        if (vch.empty()) return "0";
        std::string s;
        for (auto it = vch.rbegin(); it != vch.rend(); ++it)
        {
            char buf[3];
            sprintf(buf, "%02x", *it);
            s += buf;
        }
        return s;
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        return ::GetSerializeSize(getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        ::Serialize(s, getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion);
        setvch(vch);
    }

    CBigNum pow(int e) const { return pow(CBigNum(e)); }
    CBigNum pow(const CBigNum& e) const
    {
        boost::multiprecision::cpp_int r = 1;
        boost::multiprecision::cpp_int base = bn;
        boost::multiprecision::cpp_int exp = e.bn;
        if (exp < 0) { base = 1/base; exp = -exp; }
        while (exp > 0)
        {
            if ((exp & 1) != 0)
                r *= base;
            exp >>= 1;
            base *= base;
        }
        return CBigNum(r);
    }

    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const
    {
        return CBigNum(cppcrypto::mod_mul(bn % m.bn, b.bn % m.bn, m.bn));
    }

    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const
    {
        if (m.bn == 0) throw bignum_error("CBigNum::pow_mod : modulus is zero");
        boost::multiprecision::cpp_int base = bn % m.bn;
        boost::multiprecision::cpp_int exp = e.bn;
        if (exp < 0)
        {
            base = cppcrypto::mod_inverse(base, m.bn);
            exp = -exp;
        }
        boost::multiprecision::cpp_int r = 1;
        while (exp > 0)
        {
            if (exp & 1)
                r = cppcrypto::mod_mul(r, base, m.bn);
            exp >>= 1;
            base = cppcrypto::mod_mul(base, base, m.bn);
        }
        return CBigNum(r % m.bn);
    }

    CBigNum inverse(const CBigNum& m) const
    {
        return CBigNum(cppcrypto::mod_inverse((bn % m.bn + m.bn) % m.bn, m.bn));
    }

    static CBigNum generatePrime(unsigned int bits, bool safe = false)
    {
        if(bits == 0) return CBigNum(0);
        while(true)
        {
            CBigNum p = RandKBitBignum(bits);
            if (!p.isPrime()) continue;
            if (safe)
            {
                CBigNum q = (p - 1) / 2;
                if(!q.isPrime()) continue;
            }
            return p;
        }
    }

    CBigNum gcd(const CBigNum& b) const
    {
        boost::multiprecision::cpp_int a = bn;
        boost::multiprecision::cpp_int bb = b.bn;
        while (bb != 0)
        {
            boost::multiprecision::cpp_int t = bb;
            bb = a % bb;
            a = t;
        }
        return CBigNum(a);
    }

    bool isPrime(int checks=25) const
    {
        using boost::multiprecision::cpp_int;
        cpp_int a = bn;
        if (a < 2) return false;
        if (boost::multiprecision::miller_rabin_test(a, checks))
            return true;
        return false;
    }

    bool isOne() const { return bn == 1; }

    bool operator!() const { return bn == 0; }

    CBigNum& operator+=(const CBigNum& b) { bn += b.bn; return *this; }
    CBigNum& operator-=(const CBigNum& b) { bn -= b.bn; return *this; }
    CBigNum& operator*=(const CBigNum& b) { bn *= b.bn; return *this; }
    CBigNum& operator/=(const CBigNum& b) { bn /= b.bn; return *this; }
    CBigNum& operator%=(const CBigNum& b) { bn %= b.bn; return *this; }
    CBigNum& operator<<=(unsigned int shift) { bn <<= shift; return *this; }
    CBigNum& operator>>=(unsigned int shift) { bn >>= shift; return *this; }

    CBigNum& operator++() { bn += 1; return *this; }
    CBigNum operator++(int) { CBigNum ret(*this); bn += 1; return ret; }
    CBigNum& operator--() { bn -= 1; return *this; }
    CBigNum operator--(int) { CBigNum ret(*this); bn -= 1; return ret; }
};

inline CBigNum operator+(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn + b.bn); }
inline CBigNum operator-(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn - b.bn); }
inline CBigNum operator-(const CBigNum& a) { return CBigNum(-a.bn); }
inline CBigNum operator*(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn * b.bn); }
inline CBigNum operator/(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn / b.bn); }
inline CBigNum operator%(const CBigNum& a, const CBigNum& b) { return CBigNum(a.bn % b.bn); }
inline CBigNum operator<<(const CBigNum& a, unsigned int shift) { return CBigNum(a.bn << shift); }
inline CBigNum operator>>(const CBigNum& a, unsigned int shift) { return CBigNum(a.bn >> shift); }

inline bool operator==(const CBigNum& a, const CBigNum& b) { return a.bn == b.bn; }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return a.bn != b.bn; }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return a.bn <= b.bn; }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return a.bn >= b.bn; }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return a.bn < b.bn; }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return a.bn > b.bn; }

inline std::ostream& operator<<(std::ostream& strm, const CBigNum& b) { return strm << b.ToString(); }

typedef CBigNum Bignum;

#endif
