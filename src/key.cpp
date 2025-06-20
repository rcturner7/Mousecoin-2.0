// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "key.h"

static secp256k1_context* secp256k1_ctx = NULL;

static void ensure_secp256k1_init() {
    if (secp256k1_ctx == NULL) {
        secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    if (!eckey) return 0;
    ensure_secp256k1_init();

    unsigned char seckey[32];
    if (!BN_bn2binpad(priv_key, seckey, sizeof(seckey)))
        return 0;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, seckey))
        return 0;

    unsigned char pub[65];
    size_t publen = sizeof(pub);
    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    const unsigned char* pbegin = pub;
    EC_KEY_set_private_key(eckey, priv_key);
    if (o2i_ECPublicKey(&eckey, &pbegin, publen) == NULL)
        return 0;
    return 1;
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;
    ensure_secp256k1_init();

    unsigned char compact_sig[64];
    if (!BN_bn2binpad(ecsig->r, compact_sig, 32)) return 0;
    if (!BN_bn2binpad(ecsig->s, compact_sig + 32, 32)) return 0;

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &sig, compact_sig, recid))
        return 0;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(secp256k1_ctx, &pubkey, &sig, msg))
        return 0;

    unsigned char pub[65];
    size_t publen = sizeof(pub);
    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    const unsigned char* pbegin = pub;
    if (o2i_ECPublicKey(&eckey, &pbegin, publen) == NULL)
        return 0;
    return 1;
}

void CKey::SetCompressedPubKey()
{
    EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
    fCompressedPubKey = true;
}

void CKey::Reset()
{
    fCompressedPubKey = false;
    if (pkey != NULL)
        EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    fSet = false;
}

CKey::CKey()
{
    pkey = NULL;
    Reset();
}

CKey::CKey(const CKey& b)
{
    pkey = EC_KEY_dup(b.pkey);
    if (pkey == NULL)
        throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    fSet = b.fSet;
}

CKey& CKey::operator=(const CKey& b)
{
    if (!EC_KEY_copy(pkey, b.pkey))
        throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
    fSet = b.fSet;
    return (*this);
}

CKey::~CKey()
{
    EC_KEY_free(pkey);
}

bool CKey::IsNull() const
{
    return !fSet;
}

bool CKey::IsCompressed() const
{
    return fCompressedPubKey;
}

int CompareBigEndian(const unsigned char *c1, size_t c1len, const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1)
            return 1;
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2)
            return -1;
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2)
            return 1;
        if (*c2 > *c1)
            return -1;
        c1++;
        c2++;
        c1len--;
    }
    return 0;
}

// Order of secp256k1's generator minus 1.
const unsigned char vchMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
const unsigned char vchMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

const unsigned char vchZero[0] = {};

bool CKey::CheckSignatureElement(const unsigned char *vch, int len, bool half) {
    return CompareBigEndian(vch, len, vchZero, 0) > 0 &&
           CompareBigEndian(vch, len, half ? vchMaxModHalfOrder : vchMaxModOrder, 32) <= 0;
}

void CKey::MakeNewKey(bool fCompressed)
{
    if (!EC_KEY_generate_key(pkey))
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    if (fCompressed)
        SetCompressedPubKey();
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
    {
        // In testing, d2i_ECPrivateKey can return true
        // but fill in pkey with a key that fails
        // EC_KEY_check_key, so:
        if (EC_KEY_check_key(pkey))
        {
            fSet = true;
            return true;
        }
    }
    // If vchPrivKey data is bad d2i_ECPrivateKey() can
    // leave pkey in a state where calling EC_KEY_free()
    // crashes. To avoid that, set pkey to NULL and
    // leak the memory (a leak is better than a crash)
    pkey = NULL;
    Reset();
    return false;
}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
    if (vchSecret.size() != 32)
        throw key_error("CKey::SetSecret() : secret must be 32 bytes");
    BIGNUM *bn = BN_bin2bn(&vchSecret[0],32,BN_new());
    if (bn == NULL)
        throw key_error("CKey::SetSecret() : BN_bin2bn failed");
    if (!EC_KEY_regenerate_key(pkey,bn))
    {
        BN_clear_free(bn);
        throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
    }
    BN_clear_free(bn);
    fSet = true;
    if (fCompressed || fCompressedPubKey)
        SetCompressedPubKey();
    return true;
}

CSecret CKey::GetSecret(bool &fCompressed) const
{
    CSecret vchRet;
    vchRet.resize(32);
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
    int nBytes = BN_num_bytes(bn);
    if (bn == NULL)
        throw key_error("CKey::GetSecret() : EC_KEY_get0_private_key failed");
    int n=BN_bn2bin(bn,&vchRet[32 - nBytes]);
    if (n != nBytes)
        throw key_error("CKey::GetSecret(): BN_bn2bin failed");
    fCompressed = fCompressedPubKey;
    return vchRet;
}

CPrivKey CKey::GetPrivKey() const
{
    int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    CPrivKey vchPrivKey(nSize, 0);
    unsigned char* pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    return vchPrivKey;
}

bool CKey::SetPubKey(const CPubKey& vchPubKey)
{
    const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
    if (o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.vchPubKey.size()))
    {
        fSet = true;
        if (vchPubKey.vchPubKey.size() == 33)
            SetCompressedPubKey();
        return true;
    }
    pkey = NULL;
    Reset();
    return false;
}

CPubKey CKey::GetPubKey() const
{
    int nSize = i2o_ECPublicKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
    std::vector<unsigned char> vchPubKey(nSize, 0);
    unsigned char* pbegin = &vchPubKey[0];
    if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
    return CPubKey(vchPubKey);
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
    vchSig.clear();
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig == NULL)
        return false;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    const EC_GROUP *group = EC_KEY_get0_group(pkey);
    BIGNUM *order = BN_CTX_get(ctx);
    BIGNUM *halforder = BN_CTX_get(ctx);
    EC_GROUP_get_order(group, order, ctx);
    BN_rshift1(halforder, order);
    if (BN_cmp(sig->s, halforder) > 0) {
        // enforce low S values, by negating the value (modulo the order) if above order/2.
        BN_sub(sig->s, order, sig->s);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    unsigned int nSize = ECDSA_size(pkey);
    vchSig.resize(nSize); // Make sure it is big enough
    unsigned char *pos = &vchSig[0];
    nSize = i2d_ECDSA_SIG(sig, &pos);
    ECDSA_SIG_free(sig);
    vchSig.resize(nSize); // Shrink to fit actual size
    return true;
}

// create a compact signature (65 bytes), which allows reconstructing the used public key
// The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
// The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
//                  0x1D = second key with even y, 0x1E = second key with odd y
bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
    bool fOk = false;
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig==NULL)
        return false;
    vchSig.clear();
    vchSig.resize(65,0);
    int nBitsR = BN_num_bits(sig->r);
    int nBitsS = BN_num_bits(sig->s);
    if (nBitsR <= 256 && nBitsS <= 256)
    {
        int nRecId = -1;
        for (int i=0; i<4; i++)
        {
            CKey keyRec;
            keyRec.fSet = true;
            if (fCompressedPubKey)
                keyRec.SetCompressedPubKey();
            if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
                if (keyRec.GetPubKey() == this->GetPubKey())
                {
                    nRecId = i;
                    break;
                }
        }

        if (nRecId == -1)
        {
            ECDSA_SIG_free(sig);
            throw key_error("CKey::SignCompact() : unable to construct recoverable key");
        }

        vchSig[0] = nRecId+27+(fCompressedPubKey ? 4 : 0);
        BN_bn2bin(sig->r,&vchSig[33-(nBitsR+7)/8]);
        BN_bn2bin(sig->s,&vchSig[65-(nBitsS+7)/8]);
        fOk = true;
    }
    ECDSA_SIG_free(sig);
    return fOk;
}

// reconstruct public key from a compact signature
// This is only slightly more CPU intensive than just verifying it.
// If this function succeeds, the recovered public key is guaranteed to be valid
// (the signature is a valid signature of the given data for that key)
bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() != 65)
        return false;
    int nV = vchSig[0];
    if (nV<27 || nV>=35)
        return false;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BN_bin2bn(&vchSig[1],32,sig->r);
    BN_bin2bn(&vchSig[33],32,sig->s);

    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (nV >= 31)
    {
        SetCompressedPubKey();
        nV -= 4;
    }
    if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
    {
        fSet = true;
        ECDSA_SIG_free(sig);
        return true;
    }
    ECDSA_SIG_free(sig);
    return false;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    // -1 = error, 0 = bad sig, 1 = good
    if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
        return false;

    return true;
}

bool CKey::IsValid()
{
    if (!fSet)
        return false;

    if (!EC_KEY_check_key(pkey))
        return false;

    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    key2.SetSecret(secret, fCompr);
    return GetPubKey() == key2.GetPubKey();
}

bool ECC_InitSanityCheck() {
    ensure_secp256k1_init();
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if(pkey == NULL)
        return false;
    EC_KEY_free(pkey);

    // TODO Is there more EC functionality that could be missing?
    return true;
}
