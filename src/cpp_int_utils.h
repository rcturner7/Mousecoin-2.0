#ifndef CPP_INT_UTILS_H
#define CPP_INT_UTILS_H

#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
#include <openssl/bn.h>

namespace cppcrypto {
using boost::multiprecision::cpp_int;

inline cpp_int bytes_to_int(const unsigned char* data, size_t len)
{
    cpp_int result = 0;
    for (size_t i = 0; i < len; ++i) {
        result <<= 8;
        result |= data[i];
    }
    return result;
}

inline void int_to_bytes(const cpp_int& value, unsigned char* out, size_t len)
{
    cpp_int tmp = value;
    for (size_t i = 0; i < len; ++i) {
        out[len - 1 - i] = static_cast<unsigned char>(tmp & 0xff);
        tmp >>= 8;
    }
}

inline cpp_int mod_inverse(cpp_int a, cpp_int n)
{
    cpp_int t = 0, newt = 1;
    cpp_int r = n, newr = a % n;
    while (newr != 0) {
        cpp_int q = r / newr;
        cpp_int tmp = t - q * newt;
        t = newt;
        newt = tmp;
        tmp = r - q * newr;
        r = newr;
        newr = tmp;
    }
    if (r > 1) return 0;
    if (t < 0) t += n;
    return t;
}

inline cpp_int mod_mul(const cpp_int& a, const cpp_int& b, const cpp_int& mod)
{
    return (a * b) % mod;
}

inline cpp_int bignum_to_cpp_int(const BIGNUM* bn)
{
    int nBytes = BN_num_bytes(bn);
    std::vector<unsigned char> buf(nBytes ? nBytes : 1);
    BN_bn2bin(bn, buf.data());
    return bytes_to_int(buf.data(), buf.size());
}

inline void cpp_int_to_bignum(const cpp_int& value, BIGNUM* bn)
{
    size_t nBytes = (boost::multiprecision::msb(value) + 8) / 8;
    if (nBytes == 0) nBytes = 1;
    std::vector<unsigned char> buf(nBytes);
    int_to_bytes(value, buf.data(), nBytes);
    BN_bin2bn(buf.data(), nBytes, bn);
}

} // namespace cppcrypto

#endif // CPP_INT_UTILS_H
