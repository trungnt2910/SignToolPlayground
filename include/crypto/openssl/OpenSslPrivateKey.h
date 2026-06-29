#ifndef CCKY_OPENSSL_PRIVATE_KEY_H
#define CCKY_OPENSSL_PRIVATE_KEY_H

#include "crypto/PrivateKey.h"
#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

class OpenSslPrivateKey : public PrivateKey
{
  public:
    OpenSslPrivateKey(EVPPKeyPtr pkey) : m_pkey(std::move(pkey)) {}

    std::string getContainerName() const override { return ""; }
    std::string getProviderName() const override { return ""; }
    uint32_t getProviderType() const override { return 0; }
    uint32_t getKeySpec() const override { return 0; }

    const EVPPKeyPtr& getInternal() const { return m_pkey; }

  private:
    EVPPKeyPtr m_pkey;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_PRIVATE_KEY_H
