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
    static std::string calculateSha256(const std::string& filePath);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_FACTORY_H
