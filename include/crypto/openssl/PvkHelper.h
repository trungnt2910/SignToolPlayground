#ifndef CCKY_PVK_HELPER_H
#define CCKY_PVK_HELPER_H

#include <cstdint>
#include <vector>

#include "crypto/PvkKey.h"
#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

constexpr uint32_t CALG_RSA_KEYX = 0x0000a400;
constexpr uint32_t CALG_RSA_SIGN = 0x00002400;

class PvkHelper
{
  public:
    // Convert raw PRIVATEKEYBLOB bytes to OpenSSL EVP_PKEY
    static EVPPKeyPtr blobToPkey(const std::vector<uint8_t>& blob);
    // Convert OpenSSL EVP_PKEY to raw PRIVATEKEYBLOB bytes (RSA2 magic)
    static std::vector<uint8_t> pkeyToBlob(
        EVP_PKEY* pkey, PvkKeySpec keySpec = PvkKeySpec::KeyExchange);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_PVK_HELPER_H
