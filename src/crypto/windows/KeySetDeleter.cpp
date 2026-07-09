#include "crypto/windows/KeySetDeleter.h"

#include <vector>

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include "crypto/windows/Win32Cert.h"
#include "crypto/windows/Win32Helper.h"

namespace ccky
{
namespace crypto
{

KeySetDeleter::KeySetDeleter(
    std::wstring containerName, std::wstring providerName, DWORD providerType)
    : m_containerName(std::move(containerName)), m_providerName(std::move(providerName)),
      m_providerType(providerType), m_active(true)
{
}

KeySetDeleter::KeySetDeleter(const CertificatePtr& cert) : m_providerType(0), m_active(true)
{
    if (cert)
    {
        auto* winCert = dynamic_cast<Win32Cert*>(cert.get());
        if (winCert && winCert->getInternal())
        {
            initFromCertContext(winCert->getInternal());
        }
    }
}

KeySetDeleter::KeySetDeleter(PCCERT_CONTEXT pCert) : m_providerType(0), m_active(true)
{
    initFromCertContext(pCert);
}

KeySetDeleter::KeySetDeleter(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv)
    : m_providerType(0), m_active(true)
{
    initFromHandle(hKeyOrProv);
}

KeySetDeleter::~KeySetDeleter()
{
    if (!m_active || m_containerName.empty())
    {
        return;
    }

    if (m_providerType != 0)
    {
        HCRYPTPROV hDel = 0;
        CryptAcquireContextW(&hDel, m_containerName.c_str(),
            m_providerName.empty() ? nullptr : m_providerName.c_str(), m_providerType,
            CRYPT_DELETEKEYSET);
        // According to MS Docs:
        // When this flag is set, the value returned in phProv is undefined,
        // and thus, the CryptReleaseContext function need not be called afterward.
    }
    else
    {
        NCRYPT_PROV_HANDLE hProv = 0;
        if (NCryptOpenStorageProvider(&hProv,
                m_providerName.empty() ? nullptr : m_providerName.c_str(), 0) == ERROR_SUCCESS)
        {
            NCRYPT_KEY_HANDLE hKey = 0;
            if (NCryptOpenKey(hProv, &hKey, m_containerName.c_str(), 0, 0) == ERROR_SUCCESS)
            {
                NCryptDeleteKey(hKey, 0);
            }
            NCryptFreeObject(hProv);
        }
    }
}

void KeySetDeleter::dismiss() { m_active = false; }

void KeySetDeleter::initFromCertContext(PCCERT_CONTEXT pCert)
{
    if (!pCert)
    {
        return;
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) &&
        size > 0)
    {
        std::vector<uint8_t> buf(size);
        if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
        {
            auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
            if (info->pwszContainerName)
            {
                m_containerName = info->pwszContainerName;
            }
            if (info->pwszProvName)
            {
                m_providerName = info->pwszProvName;
            }
            m_providerType = info->dwProvType;
        }
    }
}

void KeySetDeleter::initFromHandle(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv)
{
    if (hKeyOrProv == 0)
    {
        return;
    }
    DWORD cbSize = 0;
    if (CryptGetProvParam(hKeyOrProv, PP_CONTAINER, nullptr, &cbSize, 0))
    {
        std::vector<char> buf(cbSize);
        if (CryptGetProvParam(
                hKeyOrProv, PP_CONTAINER, reinterpret_cast<BYTE*>(buf.data()), &cbSize, 0))
        {
            m_containerName = Win32Helper::utf8ToWide(buf.data());
        }
        DWORD provType = 0;
        DWORD provTypeSize = sizeof(provType);
        if (CryptGetProvParam(
                hKeyOrProv, PP_PROVTYPE, reinterpret_cast<BYTE*>(&provType), &provTypeSize, 0))
        {
            m_providerType = provType;
        }
        cbSize = 0;
        if (CryptGetProvParam(hKeyOrProv, PP_NAME, nullptr, &cbSize, 0) && cbSize > 0)
        {
            std::vector<char> provBuf(cbSize);
            if (CryptGetProvParam(
                    hKeyOrProv, PP_NAME, reinterpret_cast<BYTE*>(provBuf.data()), &cbSize, 0))
            {
                m_providerName = Win32Helper::utf8ToWide(provBuf.data());
            }
        }
    }
    else if (NCryptGetProperty(hKeyOrProv, NCRYPT_NAME_PROPERTY, nullptr, 0, &cbSize, 0) ==
             ERROR_SUCCESS)
    {
        std::vector<wchar_t> nameBuf(cbSize / sizeof(wchar_t));
        if (NCryptGetProperty(hKeyOrProv, NCRYPT_NAME_PROPERTY,
                reinterpret_cast<PBYTE>(nameBuf.data()), cbSize, &cbSize, 0) == ERROR_SUCCESS)
        {
            m_containerName = nameBuf.data();
        }
        m_providerType = 0;
    }
}

} // namespace crypto
} // namespace ccky
