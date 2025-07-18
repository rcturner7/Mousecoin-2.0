#include <boost/test/unit_test.hpp>

#include "main.h"
#include "wallet.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE(base64_tests)

BOOST_AUTO_TEST_CASE(base64_testvectors)
{
    static const std::string vstrIn[]  = {"","f","fo","foo","foob","fooba","foobar"};
    static const std::string vstrOut[] = {"","Zg==","Zm8=","Zm9v","Zm9vYg==","Zm9vYmE=","Zm9vYmFy"};
    for (unsigned int i=0; i<sizeof(vstrIn)/sizeof(vstrIn[0]); i++)
    {
        std::string strEnc = EncodeBase64(vstrIn[i]);
        BOOST_CHECK(strEnc == vstrOut[i]);
        std::string strDec = DecodeBase64(strEnc);
        BOOST_CHECK(strDec == vstrIn[i]);
    }

    {
        bool fInvalid = false;
        std::vector<unsigned char> vchRet;

        vchRet = DecodeBase64("!!", &fInvalid);
        BOOST_CHECK(fInvalid || vchRet.empty());
        BOOST_CHECK(DecodeBase64("!!").empty());

        fInvalid = false;
        vchRet = DecodeBase64("Zg", &fInvalid);
        BOOST_CHECK(fInvalid);

        fInvalid = false;
        vchRet = DecodeBase64("Zg=", &fInvalid);
        BOOST_CHECK(fInvalid);

        fInvalid = false;
        vchRet = DecodeBase64("Zg===", &fInvalid);
        BOOST_CHECK(fInvalid);
    }
}

BOOST_AUTO_TEST_SUITE_END()
