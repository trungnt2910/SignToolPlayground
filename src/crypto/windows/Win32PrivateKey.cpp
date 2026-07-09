#include "crypto/windows/Win32PrivateKey.h"

#include <vector>

#include <windows.h>

#include <wincrypt.h>

#include "crypto/CckyProbeAllocate.h"
#include "crypto/windows/Win32Helper.h"

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
    std::vector<uint8_t> buf;
    if (CckyProbeAllocate<CertGetCertificateContextProperty, CckyProbeReturnPositive{}>(
            m_pCertContext.get(), CERT_KEY_PROV_INFO_PROP_ID, CckyProbeBuffer(buf),
            CckyProbeBytesRef<DWORD>()))
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
    return Win32Helper::wideToUtf8(m_wContainerName);
}

std::string Win32PrivateKey::getProviderName() const
{
    return Win32Helper::wideToUtf8(m_wProviderName);
}

const CERT_PUBLIC_KEY_INFO* Win32PrivateKey::getPublicKeyInfo() const
{
    if (m_pCertContext != nullptr)
    {
        return &m_pCertContext->pCertInfo->SubjectPublicKeyInfo;
    }
    if (m_hProv == nullptr)
    {
        return nullptr;
    }
    if (m_publicKeyInfoBuf.empty())
    {
        if (!CckyProbeAllocate<CryptExportPublicKeyInfo, CckyProbeReturnPositive{}>(m_hProv.get(),
                m_keySpec, X509_ASN_ENCODING, CckyProbeBuffer(m_publicKeyInfoBuf),
                CckyProbeBytesRef<DWORD>()))
        {
            return nullptr;
        }
    }
    return reinterpret_cast<const CERT_PUBLIC_KEY_INFO*>(m_publicKeyInfoBuf.data());
}

} // namespace crypto
} // namespace ccky
