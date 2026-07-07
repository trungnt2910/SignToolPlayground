#include "crypto/windows/Win32PrivateKey.h"

#include "crypto/windows/WinHelper.h"

namespace ccky
{
namespace crypto
{

Win32PrivateKey::Win32PrivateKey(CryptProvPtr hProv, CryptKeyPtr hKey,
    const std::wstring& wContainerName, const std::wstring& wProviderName, uint32_t providerType,
    uint32_t keySpec, std::unique_ptr<KeySetDeleter> keysetDeleter)
    : m_hProv(std::move(hProv)), m_hKey(std::move(hKey)), m_wContainerName(wContainerName),
      m_wProviderName(wProviderName), m_providerType(providerType), m_keySpec(keySpec),
      m_isTempContainer(keysetDeleter != nullptr), m_keysetDeleter(std::move(keysetDeleter))
{
}

Win32PrivateKey::Win32PrivateKey(CertContextPtr pCertContext)
    : m_pCertContext(std::move(pCertContext)), m_providerType(0), m_keySpec(0),
      m_isTempContainer(false)
{
    if (m_pCertContext == nullptr)
    {
        return;
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(
            m_pCertContext.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) &&
        size > 0)
    {
        std::vector<uint8_t> buf(size);
        if (CertGetCertificateContextProperty(
                m_pCertContext.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
        {
            auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
            if (info->pwszContainerName)
            {
                m_wContainerName = info->pwszContainerName;
            }
            if (info->pwszProvName)
            {
                m_wProviderName = info->pwszProvName;
            }
            m_providerType = info->dwProvType;
            m_keySpec = info->dwKeySpec;
        }
    }
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    if (CryptAcquireCertificatePrivateKey(m_pCertContext.get(),
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr, &hKeyOrProv,
            &dwKeySpec, &fCallerFree))
    {
        if (dwKeySpec != CERT_NCRYPT_KEY_SPEC)
        {
            if (fCallerFree)
            {
                m_hProv.reset(hKeyOrProv);
            }
            else
            {
                CryptContextAddRef(hKeyOrProv, nullptr, 0);
                m_hProv.reset(hKeyOrProv);
            }
            HCRYPTKEY hKey = 0;
            if (CryptGetUserKey(
                    m_hProv.get(), m_keySpec != 0 ? m_keySpec : AT_KEYEXCHANGE, &hKey) ||
                CryptGetUserKey(m_hProv.get(), AT_SIGNATURE, &hKey))
            {
                m_hKey.reset(hKey);
            }
        }
        else if (fCallerFree)
        {
            NCryptFreeObject(hKeyOrProv);
        }
    }
}

Win32PrivateKey::~Win32PrivateKey()
{
    m_hKey.reset();
    m_hProv.reset();
}

std::string Win32PrivateKey::getContainerName() const
{
    return WinHelper::wideToUtf8(m_wContainerName);
}

std::string Win32PrivateKey::getProviderName() const
{
    return WinHelper::wideToUtf8(m_wProviderName);
}

const CERT_PUBLIC_KEY_INFO* Win32PrivateKey::getPublicKeyInfo() const
{
    if (m_pCertContext != nullptr)
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
