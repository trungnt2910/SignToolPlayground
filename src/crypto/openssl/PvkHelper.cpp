#include "crypto/openssl/PvkHelper.h"

#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>
#include <openssl/param_build.h>

namespace ccky
{
namespace crypto
{

EVPPKeyPtr PvkHelper::blobToPkey(const std::vector<uint8_t>& keyData)
{
    if (keyData.size() < 20)
    {
        throw std::runtime_error("PVK key data too short");
    }

    uint8_t bType = keyData[0];
    uint8_t bVersion = keyData[1];
    if (bType != 0x07 || bVersion != 0x02)
    {
        throw std::runtime_error("Unsupported key blob type or version");
    }

    auto readU32LE = [](const uint8_t* p) -> uint32_t
    {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    };

    uint32_t aiKeyAlg = readU32LE(&keyData[4]);
    if (aiKeyAlg != CALG_RSA_KEYX && aiKeyAlg != CALG_RSA_SIGN)
    {
        throw std::runtime_error("Unsupported key algorithm in PVK");
    }

    if (std::memcmp(&keyData[8], "RSA2", 4) != 0)
    {
        throw std::runtime_error("Invalid RSA2 magic in PVK");
    }

    uint32_t bitlen = readU32LE(&keyData[12]);
    uint32_t pubexp = readU32LE(&keyData[16]);

    size_t n_len = bitlen / 8;
    size_t p_len = bitlen / 16;

    size_t expected_size = 20 + n_len + 5 * p_len + n_len;
    if (keyData.size() < expected_size)
    {
        throw std::runtime_error("PVK key data size mismatch");
    }

    size_t offset = 20;
    auto readBN = [&](size_t len)
    {
        std::vector<uint8_t> temp(len);
        for (size_t i = 0; i < len; ++i)
        {
            temp[i] = keyData[offset + len - 1 - i];
        }
        BIGNUM* raw_bn = BN_bin2bn(temp.data(), len, nullptr);
        if (!raw_bn)
        {
            throw std::runtime_error("Failed to parse BIGNUM");
        }
        BNPtr bn(raw_bn);
        offset += len;
        return bn;
    };

    BNPtr n = readBN(n_len);
    BNPtr p = readBN(p_len);
    BNPtr q = readBN(p_len);
    BNPtr dmp1 = readBN(p_len);
    BNPtr dmq1 = readBN(p_len);
    BNPtr iqmp = readBN(p_len);
    BNPtr d = readBN(n_len);

    BIGNUM* raw_e = BN_new();
    if (!raw_e)
    {
        throw std::runtime_error("Failed to allocate BIGNUM");
    }
    BNPtr e(raw_e);
    BN_set_word(e.get(), pubexp);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> ctx_guard(ctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
    {
        throw std::runtime_error("Failed to init EVP_PKEY_fromdata");
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld)
    {
        throw std::runtime_error("Failed to create OSSL_PARAM_BLD");
    }
    std::unique_ptr<OSSL_PARAM_BLD, void (*)(OSSL_PARAM_BLD*)> bld_guard(bld, OSSL_PARAM_BLD_free);

    auto pushBN = [&](const char* name, const BNPtr& bn)
    {
        if (OSSL_PARAM_BLD_push_BN(bld, name, bn.get()) <= 0)
        {
            throw std::runtime_error(std::string("Failed to push BN: ") + name);
        }
    };

    pushBN("n", n);
    pushBN("e", e);
    pushBN("d", d);
    pushBN("rsa-factor1", p);
    pushBN("rsa-factor2", q);
    pushBN("rsa-exponent1", dmp1);
    pushBN("rsa-exponent2", dmq1);
    pushBN("rsa-coefficient1", iqmp);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    if (!params)
    {
        throw std::runtime_error("Failed to build params");
    }
    std::unique_ptr<OSSL_PARAM, void (*)(OSSL_PARAM*)> params_guard(params, OSSL_PARAM_free);

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx, &raw_pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    {
        throw std::runtime_error("Failed to create EVP_PKEY from data");
    }

    return EVPPKeyPtr(raw_pkey);
}

std::vector<uint8_t> PvkHelper::pkeyToBlob(EVP_PKEY* pkey, uint32_t keySpec)
{
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
    {
        throw std::runtime_error("Invalid or non-RSA EVP_PKEY");
    }

    auto getBNParam = [](EVP_PKEY* k, const char* name) -> BNPtr
    {
        BIGNUM* raw_bn = nullptr;
        if (EVP_PKEY_get_bn_param(k, name, &raw_bn) <= 0)
        {
            throw std::runtime_error(std::string("Failed to get BN param: ") + name);
        }
        return BNPtr(raw_bn);
    };

    BNPtr n = getBNParam(pkey, "n");
    BNPtr e = getBNParam(pkey, "e");
    BNPtr d = getBNParam(pkey, "d");
    BNPtr p = getBNParam(pkey, "rsa-factor1");
    BNPtr q = getBNParam(pkey, "rsa-factor2");
    BNPtr dmp1 = getBNParam(pkey, "rsa-exponent1");
    BNPtr dmq1 = getBNParam(pkey, "rsa-exponent2");
    BNPtr iqmp = getBNParam(pkey, "rsa-coefficient1");

    uint32_t pubexp = static_cast<uint32_t>(BN_get_word(e.get()));
    uint32_t bitlen = BN_num_bits(n.get());

    size_t n_len = bitlen / 8;
    size_t p_len = bitlen / 16;

    size_t expected_size = 20 + n_len + 5 * p_len + n_len;
    std::vector<uint8_t> keyData(expected_size, 0);

    keyData[0] = 0x07; // PRIVATEKEYBLOB
    keyData[1] = 0x02; // Version 2
    keyData[2] = 0;    // Reserved
    keyData[3] = 0;    // Reserved

    auto writeU32LE = [](uint32_t val, uint8_t* ptr)
    {
        ptr[0] = static_cast<uint8_t>(val & 0xFF);
        ptr[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        ptr[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        ptr[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    };

    uint32_t aiKeyAlg = (keySpec == KEYSPEC_SIGN) ? CALG_RSA_SIGN : CALG_RSA_KEYX;
    writeU32LE(aiKeyAlg, &keyData[4]);
    std::memcpy(&keyData[8], "RSA2", 4);
    writeU32LE(bitlen, &keyData[12]);
    writeU32LE(pubexp, &keyData[16]);

    size_t offset = 20;
    auto writeBN = [&](const BIGNUM* bn, size_t len)
    {
        std::vector<uint8_t> temp(len, 0);
        BN_bn2binpad(bn, temp.data(), len);
        for (size_t i = 0; i < len; ++i)
        {
            keyData[offset + i] = temp[len - 1 - i];
        }
        offset += len;
    };

    writeBN(n.get(), n_len);
    writeBN(p.get(), p_len);
    writeBN(q.get(), p_len);
    writeBN(dmp1.get(), p_len);
    writeBN(dmq1.get(), p_len);
    writeBN(iqmp.get(), p_len);
    writeBN(d.get(), n_len);

    return keyData;
}

} // namespace crypto
} // namespace ccky
