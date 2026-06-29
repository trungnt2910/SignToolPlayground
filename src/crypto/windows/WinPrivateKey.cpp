#include "crypto/windows/WinPrivateKey.h"

#include "crypto/windows/WinHelper.h"

namespace ccky
{
namespace crypto
{

WinPrivateKey::WinPrivateKey(CryptProvPtr hProv, CryptKeyPtr hKey,
    const std::wstring& wContainerName, const std::wstring& wProviderName, uint32_t providerType,
    uint32_t keySpec, std::unique_ptr<KeySetDeleter> keysetDeleter)
    : m_hProv(std::move(hProv)), m_hKey(std::move(hKey)), m_wContainerName(wContainerName),
      m_wProviderName(wProviderName), m_providerType(providerType), m_keySpec(keySpec),
      m_isTempContainer(keysetDeleter != nullptr), m_keysetDeleter(std::move(keysetDeleter))
{
}

WinPrivateKey::WinPrivateKey(CertContextPtr pCertContext)
    : m_pCertContext(std::move(pCertContext)), m_providerType(0), m_keySpec(0),
      m_isTempContainer(false)
{
}

WinPrivateKey::~WinPrivateKey()
{
    m_hKey.reset();
    m_hProv.reset();
}

std::string WinPrivateKey::getContainerName() const
{
    return WinHelper::wideToUtf8(m_wContainerName);
}

std::string WinPrivateKey::getProviderName() const
{
    return WinHelper::wideToUtf8(m_wProviderName);
}

const CERT_PUBLIC_KEY_INFO* WinPrivateKey::getPublicKeyInfo() const
{
    if (m_pCertContext)
    {
        return &m_pCertContext->pCertInfo->SubjectPublicKeyInfo;
    }
    if (m_hProv.get() != 0)
    {
        if (m_publicKeyInfoBuf.empty())
        {
            DWORD cbPublicKeyInfo = 0;
            if (!CryptExportPublicKeyInfo(
                    m_hProv.get(), m_keySpec, X509_ASN_ENCODING, nullptr, &cbPublicKeyInfo))
            {
                return nullptr;
            }
            m_publicKeyInfoBuf.resize(cbPublicKeyInfo);
            if (!CryptExportPublicKeyInfo(m_hProv.get(), m_keySpec, X509_ASN_ENCODING,
                    reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(m_publicKeyInfoBuf.data()),
                    &cbPublicKeyInfo))
            {
                m_publicKeyInfoBuf.clear();
                return nullptr;
            }
        }
        return reinterpret_cast<const CERT_PUBLIC_KEY_INFO*>(m_publicKeyInfoBuf.data());
    }
    return nullptr;
}

} // namespace crypto
} // namespace ccky
