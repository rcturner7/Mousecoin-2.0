// bignum.h - replacement for legacy CBigNum
#pragma once

#include <boost/multiprecision/cpp_int.hpp>

// One alias: just use CBigNum == cpp_int for compatibility with your existing variable names.
using CBigNum = boost::multiprecision::cpp_int;
