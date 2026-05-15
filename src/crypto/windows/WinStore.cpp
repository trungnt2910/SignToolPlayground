#include "crypto/windows/WinStore.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <windows.h>

#include <imagehlp.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include "crypto/AuthenticodeSigner.h"
#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WindowsException.h"

namespace ccky
{
namespace crypto
{

// Win32CommonStore
std::vector<CertificatePtr> Win32CommonStore::getCertificates() { return m_certs; }

std::vector<CrlPtr> Win32CommonStore::getCrls() { return m_crls; }

std::vector<CtlPtr> Win32CommonStore::getCtls() { return m_ctls; }

void Win32CommonStore::addCertificate(CertificatePtr cert)
{
    if (!cert)
    {
        throw WindowsException("Invalid certificate pointer", false);
    }
    m_certs.push_back(cert);
}

void Win32CommonStore::addCrl(CrlPtr crl)
{
    if (!crl)
    {
        throw WindowsException("Invalid CRL pointer", false);
    }
    m_crls.push_back(crl);
}

void Win32CommonStore::addCtl(CtlPtr ctl)
{
    if (!ctl)
    {
        throw WindowsException("Invalid CTL pointer", false);
    }
    m_ctls.push_back(ctl);
}

void Win32CommonStore::deleteCertificate(const std::string& commonName, const std::string& sha1Hash)
{
    auto it = std::remove_if(m_certs.begin(), m_certs.end(),
        [&](const CertificatePtr& c)
        {
            if (!commonName.empty() && c->getCommonName() != commonName)
            {
                return false;
            }
            if (!sha1Hash.empty() && c->getSha1() != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_certs.erase(it, m_certs.end());
}

void Win32CommonStore::deleteCrl(const std::string& sha1Hash)
{
    auto it = std::remove_if(m_crls.begin(), m_crls.end(),
        [&](const CrlPtr& c)
        {
            if (!sha1Hash.empty() && c->getSha1() != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_crls.erase(it, m_crls.end());
}

void Win32CommonStore::deleteCtl(const std::string& sha1Hash)
{
    auto it = std::remove_if(m_ctls.begin(), m_ctls.end(),
        [&](const CtlPtr& c)
        {
            if (!sha1Hash.empty() && c->getSha1() != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_ctls.erase(it, m_ctls.end());
}

void Win32CommonStore::addPrivateKey(const std::string& pfxFilePath, const std::string& password)
{
    throw WindowsException(
        "addPrivateKey is only supported on Windows system certificate stores.", false);
}

void Win32CommonStore::deletePrivateKey(const std::string& commonName, const std::string& sha1Hash)
{
    throw WindowsException(
        "deletePrivateKey is only supported on Windows system certificate stores.", false);
}

CertificatePtr Win32CommonStore::createCert(PCCERT_CONTEXT pCert) const
{
    return std::make_shared<WinCert>(pCert);
}

void Win32CommonStore::populateFromStore(HCERTSTORE hStore)
{
    if (!hStore)
    {
        return;
    }
    CertContextPtr pCert;
    while ((pCert.reset(CertEnumCertificatesInStore(hStore, pCert.release())), pCert != nullptr))
    {
        m_certs.push_back(createCert(pCert.get()));
    }
    CrlContextPtr pCrl;
    while ((pCrl.reset(CertEnumCRLsInStore(hStore, pCrl.release())), pCrl != nullptr))
    {
        m_crls.push_back(std::make_shared<WinCrl>(pCrl.get()));
    }
    CtlContextPtr pCtl;
    while ((pCtl.reset(CertEnumCTLsInStore(hStore, pCtl.release())), pCtl != nullptr))
    {
        m_ctls.push_back(std::make_shared<WinCtl>(pCtl.get()));
    }
}

// WinSystemStoreImpl

void WinSystemStoreImpl::load(const std::string& location, const StoreOptions& options)
{
    m_store.reset();
    m_loadedLocation = location;
    DWORD dwFlags = CERT_SYSTEM_STORE_CURRENT_USER;
    if (options.registryLocation == "localMachine" || options.registryLocation == "LocalMachine")
    {
        dwFlags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }

    std::wstring wLoc = WinHelper::utf8ToWide(location);
    m_store.reset(CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0, dwFlags | CERT_STORE_OPEN_EXISTING_FLAG, wLoc.c_str()));
    if (!m_store)
    {
        m_store.reset(CertOpenSystemStoreA(0, location.c_str()));
    }
    if (!m_store)
    {
        throw WindowsException("Failed to open the system store", false);
    }
}

void WinSystemStoreImpl::save(const std::string& location, const StoreOptions& options)
{
    if (!m_store)
    {
        throw WindowsException("Failed to save the system store", false);
    }
}

std::vector<CertificatePtr> WinSystemStoreImpl::getCertificates()
{
    std::vector<CertificatePtr> list;
    if (!m_store)
    {
        return list;
    }
    CertContextPtr pCert;
    while ((
        pCert.reset(CertEnumCertificatesInStore(m_store.get(), pCert.release())), pCert != nullptr))
    {
        list.push_back(std::make_shared<WinCert>(pCert.get()));
    }
    return list;
}

std::vector<CrlPtr> WinSystemStoreImpl::getCrls()
{
    std::vector<CrlPtr> list;
    if (!m_store)
    {
        return list;
    }
    CrlContextPtr pCrl;
    while ((pCrl.reset(CertEnumCRLsInStore(m_store.get(), pCrl.release())), pCrl != nullptr))
    {
        list.push_back(std::make_shared<WinCrl>(pCrl.get()));
    }
    return list;
}

std::vector<CtlPtr> WinSystemStoreImpl::getCtls()
{
    std::vector<CtlPtr> list;
    if (!m_store)
    {
        return list;
    }
    CtlContextPtr pCtl;
    while ((pCtl.reset(CertEnumCTLsInStore(m_store.get(), pCtl.release())), pCtl != nullptr))
    {
        list.push_back(std::make_shared<WinCtl>(pCtl.get()));
    }
    return list;
}

void WinSystemStoreImpl::addCertificate(CertificatePtr cert)
{
    if (!m_store || !cert)
    {
        throw WindowsException("Invalid store handle or certificate pointer", false);
    }
    auto der = cert->getEncoded();
    if (!CertAddEncodedCertificateToStore(m_store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
    {
        throw WindowsException("Failed to add certificate to system store", false);
    }
}

void WinSystemStoreImpl::addCrl(CrlPtr crl)
{
    if (!m_store || !crl)
    {
        throw WindowsException("Invalid store handle or CRL pointer", false);
    }
    auto der = crl->getEncoded();
    if (!CertAddEncodedCRLToStore(m_store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
    {
        throw WindowsException("Failed to add CRL to system store", false);
    }
}

void WinSystemStoreImpl::addCtl(CtlPtr ctl)
{
    if (!m_store || !ctl)
    {
        throw WindowsException("Invalid store handle or CTL pointer", false);
    }
    auto der = ctl->getEncoded();
    if (!CertAddEncodedCTLToStore(m_store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
    {
        throw WindowsException("Failed to add CTL to system store", false);
    }
}

void WinSystemStoreImpl::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
{
    if (!m_store)
    {
        throw WindowsException("Invalid store handle", false);
    }
    CertContextPtr pCert;
    while ((
        pCert.reset(CertEnumCertificatesInStore(m_store.get(), pCert.release())), pCert != nullptr))
    {
        WinCert c(pCert.get());
        if (!commonName.empty() && c.getCommonName() != commonName)
        {
            continue;
        }
        if (!sha1Hash.empty() && c.getSha1() != sha1Hash)
        {
            continue;
        }

        CertContextPtr pDup(CertDuplicateCertificateContext(pCert.get()));
        if (!CertDeleteCertificateFromStore(pDup.release()))
        {
            throw WindowsException("Failed to delete certificate from system store", false);
        }
    }
}

void WinSystemStoreImpl::deleteCrl(const std::string& sha1Hash)
{
    if (!m_store)
    {
        throw WindowsException("Invalid store handle", false);
    }
    CrlContextPtr pCrl;
    while ((pCrl.reset(CertEnumCRLsInStore(m_store.get(), pCrl.release())), pCrl != nullptr))
    {
        WinCrl c(pCrl.get());
        if (!sha1Hash.empty() && c.getSha1() != sha1Hash)
        {
            continue;
        }

        CrlContextPtr pDup(CertDuplicateCRLContext(pCrl.get()));
        if (!CertDeleteCRLFromStore(pDup.release()))
        {
            throw WindowsException("Failed to delete CRL from system store", false);
        }
    }
}

void WinSystemStoreImpl::deleteCtl(const std::string& sha1Hash)
{
    if (!m_store)
    {
        throw WindowsException("Invalid store handle", false);
    }
    CtlContextPtr pCtl;
    while ((pCtl.reset(CertEnumCTLsInStore(m_store.get(), pCtl.release())), pCtl != nullptr))
    {
        WinCtl c(pCtl.get());
        if (!sha1Hash.empty() && c.getSha1() != sha1Hash)
        {
            continue;
        }

        CtlContextPtr pDup(CertDuplicateCTLContext(pCtl.get()));
        if (!CertDeleteCTLFromStore(pDup.release()))
        {
            throw WindowsException("Failed to delete CTL from system store", false);
        }
    }
}

void WinSystemStoreImpl::addPrivateKey(const std::string& pfxFilePath, const std::string& password)
{
    if (!m_store)
    {
        throw WindowsException("Invalid store handle", false);
    }
    std::ifstream file(pfxFilePath, std::ios::binary);
    if (!file.is_open())
    {
        throw WindowsException("Failed to open PFX file", false);
    }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.empty())
    {
        throw WindowsException("Failed to read PFX file", false);
    }
    CRYPT_DATA_BLOB blob{
        .cbData = static_cast<DWORD>(data.size()),
        .pbData = data.data(),
    };
    std::wstring wPass = WinHelper::utf8ToWide(password);
    CertStorePtr hPfxStore(PFXImportCertStore(&blob, wPass.c_str(), CRYPT_USER_KEYSET));
    if (!hPfxStore)
    {
        hPfxStore.reset(PFXImportCertStore(&blob, nullptr, CRYPT_USER_KEYSET));
    }
    if (!hPfxStore)
    {
        throw WindowsException("Failed to import PFX for private key addition", false);
    }
    CertContextPtr pPfxCert;
    while ((pPfxCert.reset(CertEnumCertificatesInStore(hPfxStore.get(), pPfxCert.release())),
        pPfxCert != nullptr))
    {
        if (!CertAddCertificateContextToStore(
                m_store.get(), pPfxCert.get(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
        {
            throw WindowsException("Failed to add certificate context to system store", false);
        }
    }
}

void WinSystemStoreImpl::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    if (!m_store)
    {
        throw WindowsException("Invalid store handle", false);
    }
    CertContextPtr pCert;
    while ((
        pCert.reset(CertEnumCertificatesInStore(m_store.get(), pCert.release())), pCert != nullptr))
    {
        WinCert c(pCert.get());
        if (!commonName.empty() && c.getCommonName() != commonName)
        {
            continue;
        }
        if (!sha1Hash.empty() && c.getSha1() != sha1Hash)
        {
            continue;
        }

        DWORD size = 0;
        if (CertGetCertificateContextProperty(
                pCert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size))
        {
            std::vector<uint8_t> buf(size);
            if (CertGetCertificateContextProperty(
                    pCert.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
            {
                auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
                if (info->dwProvType != 0)
                {
                    HCRYPTPROV hProv = 0;
                    DWORD flags = CRYPT_DELETEKEYSET;
                    if (info->dwFlags & CRYPT_MACHINE_KEYSET)
                    {
                        flags |= CRYPT_MACHINE_KEYSET;
                    }
                    CryptAcquireContextW(&hProv, info->pwszContainerName, info->pwszProvName,
                        info->dwProvType, flags);
                }
                else
                {
                    NCRYPT_PROV_HANDLE hProv = 0;
                    if (NCryptOpenStorageProvider(&hProv, info->pwszProvName, 0) == ERROR_SUCCESS)
                    {
                        NCRYPT_KEY_HANDLE hKey = 0;
                        DWORD flags = 0;
                        if (info->dwFlags & CRYPT_MACHINE_KEYSET)
                        {
                            flags |= NCRYPT_MACHINE_KEY_FLAG;
                        }
                        if (NCryptOpenKey(hProv, &hKey, info->pwszContainerName, info->dwKeySpec,
                                flags) == ERROR_SUCCESS)
                        {
                            NCryptDeleteKey(hKey, 0);
                        }
                        NCryptFreeObject(hProv);
                    }
                }
            }
        }

        CertContextPtr pDup(CertDuplicateCertificateContext(pCert.get()));
        if (!CertDeleteCertificateFromStore(pDup.release()))
        {
            throw WindowsException("Failed to delete certificate from system store", false);
        }
    }
}

// WinCerFileStore
void WinCerFileStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;

    if (!std::filesystem::exists(location))
    {
        return;
    }

    std::wstring wLocation = WinHelper::utf8ToWide(location);
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE rawStore = nullptr;
    HCRYPTMSG rawMsg = nullptr;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wLocation.c_str(), CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType, &dwFormatType, &rawStore,
            &rawMsg, nullptr))
    {
        CertStorePtr hStore(rawStore);
        CryptMsgPtr hMsg(rawMsg);
        if (hStore)
        {
            populateFromStore(hStore.get());
        }
        return;
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND || err == CRYPT_E_NO_MATCH)
        {
            return;
        }
        throw WindowsException("Failed to open the store", false);
    }
}

void WinCerFileStore::save(const std::string& location, const StoreOptions& options)
{
    std::ofstream file(location, std::ios::binary);
    if (!file.is_open())
    {
        throw WindowsException("Failed to save the store", false);
    }
    for (const auto& c : m_certs)
    {
        auto der = c->getEncoded();
        file.write(reinterpret_cast<const char*>(der.data()), der.size());
    }
    for (const auto& c : m_crls)
    {
        auto der = c->getEncoded();
        file.write(reinterpret_cast<const char*>(der.data()), der.size());
    }
    for (const auto& c : m_ctls)
    {
        auto der = c->getEncoded();
        file.write(reinterpret_cast<const char*>(der.data()), der.size());
    }
}

// WinPeFileStore
void WinPeFileStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;
    m_signingAlgorithm = "sha256";
    m_timestamp = "None";

    std::wstring wLocation = WinHelper::utf8ToWide(location);
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE rawStore = nullptr;
    HCRYPTMSG rawMsg = nullptr;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wLocation.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED |
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType, &dwFormatType, &rawStore,
            &rawMsg, nullptr))
    {
        CertStorePtr hStore(rawStore);
        CryptMsgPtr hMsg(rawMsg);
        if (hStore)
        {
            populateFromStore(hStore.get());
        }
        if (hMsg)
        {
            DWORD cbSize = 0;
            if (CryptMsgGetParam(hMsg.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSize))
            {
                std::vector<uint8_t> siBuf(cbSize);
                if (CryptMsgGetParam(hMsg.get(), CMSG_SIGNER_INFO_PARAM, 0, siBuf.data(), &cbSize))
                {
                    auto* pSi = reinterpret_cast<PCMSG_SIGNER_INFO>(siBuf.data());
                    if (pSi && pSi->HashAlgorithm.pszObjId)
                    {
                        std::string oid = pSi->HashAlgorithm.pszObjId;
                        if (oid == szOID_OIWSEC_sha1)
                        {
                            m_signingAlgorithm = "sha1";
                        }
                        else if (oid == szOID_NIST_sha256)
                        {
                            m_signingAlgorithm = "sha256";
                        }
                        else if (oid == szOID_NIST_sha384)
                        {
                            m_signingAlgorithm = "sha384";
                        }
                        else if (oid == szOID_NIST_sha512)
                        {
                            m_signingAlgorithm = "sha512";
                        }
                        else
                        {
                            m_signingAlgorithm = oid;
                        }
                    }
                    if (pSi && pSi->UnauthAttrs.cAttr > 0)
                    {
                        for (DWORD i = 0; i < pSi->UnauthAttrs.cAttr; ++i)
                        {
                            std::string attrOid = pSi->UnauthAttrs.rgAttr[i].pszObjId;
                            if (attrOid == szOID_RSA_counterSign ||
                                attrOid == szOID_RFC3161_counterSign)
                            {
                                m_timestamp = "Present";
                            }
                        }
                    }
                }
            }
        }
    }
    else if (GetLastError() != CRYPT_E_NO_MATCH)
    {
        throw WindowsException("Failed to open the store", false);
    }
}

void WinPeFileStore::save(const std::string& location, const StoreOptions& options)
{
    if (location != m_loadedLocation && !m_loadedLocation.empty())
    {
        std::ifstream src(m_loadedLocation, std::ios::binary);
        std::ofstream dst(location, std::ios::binary);
        dst << src.rdbuf();
        m_loadedLocation = location;
    }

    if (m_certs.empty() && m_crls.empty() && m_ctls.empty())
    {
        return;
    }

    CertStorePtr hTempStore(
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr));
    if (!hTempStore)
    {
        throw WindowsException("Failed to save the store", false);
    }

    for (const auto& c : m_certs)
    {
        auto der = c->getEncoded();
        CertAddEncodedCertificateToStore(hTempStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    }
    for (const auto& c : m_crls)
    {
        auto der = c->getEncoded();
        CertAddEncodedCRLToStore(hTempStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    }
    for (const auto& c : m_ctls)
    {
        auto der = c->getEncoded();
        CertAddEncodedCTLToStore(hTempStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), der.size(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    }

    CRYPT_DATA_BLOB p7Blob{
        .cbData = 0,
        .pbData = nullptr,
    };
    if (CertSaveStore(hTempStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &p7Blob, 0))
    {
        std::unique_ptr<BYTE[]> p7Data(new BYTE[p7Blob.cbData]);
        p7Blob.pbData = p7Data.get();
        if (CertSaveStore(hTempStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &p7Blob, 0))
        {
            std::wstring wLoc = WinHelper::utf8ToWide(m_loadedLocation);
            HandlePtr hFile(CreateFileW(wLoc.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (hFile)
            {
                DWORD dwLen = sizeof(WIN_CERTIFICATE) + p7Blob.cbData;
                std::unique_ptr<BYTE[]> winCertBuf(new BYTE[dwLen]);
                LPWIN_CERTIFICATE pWinCert = reinterpret_cast<LPWIN_CERTIFICATE>(winCertBuf.get());
                pWinCert->dwLength = dwLen;
                pWinCert->wRevision = WIN_CERT_REVISION_2_0;
                pWinCert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
                memcpy(pWinCert->bCertificate, p7Blob.pbData, p7Blob.cbData);

                DWORD dwIndex = 0;
                ImageAddCertificate(hFile.get(), pWinCert, &dwIndex);
            }
        }
    }
}

// WinPfxCertStore
void WinPfxCertStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;

    std::ifstream file(location, std::ios::binary);
    if (!file.is_open())
    {
        throw WindowsException("Failed to open the store", false);
    }

    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.empty())
    {
        throw WindowsException("Failed to open the store", false);
    }

    CRYPT_DATA_BLOB blob{
        .cbData = static_cast<DWORD>(data.size()),
        .pbData = data.data(),
    };

    std::wstring wPass = WinHelper::utf8ToWide(options.password);
    CertStorePtr hPfxStore(PFXImportCertStore(&blob, wPass.c_str(), 0));
    if (!hPfxStore)
    {
        hPfxStore.reset(PFXImportCertStore(&blob, nullptr, 0));
    }

    if (!hPfxStore)
    {
        throw WindowsException("Failed to open the store", false);
    }

    populateFromStore(hPfxStore.get());
}

CertificatePtr WinPfxCertStore::createCert(PCCERT_CONTEXT pCert) const
{
    return std::make_shared<WinPfxCert>(pCert);
}

void WinPfxCertStore::save(const std::string& location, const StoreOptions& options)
{
    throw WindowsException("Saving to PFX store is unsupported.", false);
}

} // namespace crypto
} // namespace ccky
