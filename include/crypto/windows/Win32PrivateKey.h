#ifndef CCKY_WIN32_PRIVATE_KEY_H
#define CCKY_WIN32_PRIVATE_KEY_H

#include <string>
#include <vector>

#include "crypto/PrivateKey.h"
#include "crypto/windows/KeySetDeleter.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

class Win32PrivateKey : public PrivateKey
{
  public:
    Win32PrivateKey(CryptProvPtr hProv, CryptKeyPtr hKey, const std::wstring& wContainerName,
        const std::wstring& wProviderName, uint32_t providerType, uint32_t keySpec,
        std::unique_ptr<KeySetDeleter> keysetDeleter);

    Win32PrivateKey(CertContextPtr pCertContext);

    ~Win32PrivateKey() override;

    std::string getContainerName() const override;
    std::string getProviderName() const override;
    uint32_t getProviderType() const override { return m_providerType; }
    uint32_t getKeySpec() const override { return m_keySpec; }

    HCRYPTKEY getInternalKey() const { return m_hKey.get(); }
    HCRYPTPROV getInternalProv() const { return m_hProv.get(); }
    const CERT_CONTEXT* getCertContext() const { return m_pCertContext.get(); }

    const CERT_PUBLIC_KEY_INFO* getPublicKeyInfo() const;

  private:
    CryptProvPtr m_hProv;
    CryptKeyPtr m_hKey;
    CertContextPtr m_pCertContext;
    std::wstring m_wContainerName;
    std::wstring m_wProviderName;
    uint32_t m_providerType;
    uint32_t m_keySpec;
    bool m_isTempContainer;
    std::unique_ptr<KeySetDeleter> m_keysetDeleter;
    mutable std::vector<uint8_t> m_publicKeyInfoBuf;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_PRIVATE_KEY_H
