#ifndef CCKY_CRYPTO_FACTORY_H
#define CCKY_CRYPTO_FACTORY_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "crypto/Certificate.h"
#include "crypto/ICertStore.h"

namespace ccky
{
namespace crypto
{

class CryptoFactory
{
  public:
    static const std::string& getBackendType();

    static std::shared_ptr<ICertStore> createStore(
        StoreType type, const std::string& location = "");
    static CertificatePtr createCertificateFromDer(const std::vector<uint8_t>& derBytes);
    static CrlPtr createCrlFromDer(const std::vector<uint8_t>& derBytes);
    static CtlPtr createCtlFromDer(const std::vector<uint8_t>& derBytes);
    static bool acquireContext(const std::string& container, const std::string& provider);
    static void deleteKeyContainer(
        const std::string& name, const std::string& provider = "", uint32_t providerType = 0);
    static std::string calculateSha256(const std::string& filePath);
    static std::vector<uint8_t> calculateSha1Bytes(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> encryptRc4Bytes(
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    static void getRandomBytes(void* buf, size_t len);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_FACTORY_H
