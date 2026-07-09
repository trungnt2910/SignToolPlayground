#include "crypto/CryptoFactory.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#ifndef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#endif
#include <windows.h>

#include <wincrypt.h>

#include "crypto/CckyException.h"
#include "crypto/FileTypeDetector.h"
#include "crypto/Strings.h"
#include "crypto/windows/Win32Cert.h"
#include "crypto/windows/Win32Digest.h"
#include "crypto/windows/Win32Helper.h"
#include "crypto/windows/Win32Store.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

const std::string& CryptoFactory::getBackendType()
{
    static const std::string s_backend = "windows";
    return s_backend;
}

CertificateStorePtr CryptoFactory::createStore(StoreType type, const std::string& location)
{
    switch (type)
    {
    case StoreType::WinSystem:
        return std::make_shared<Win32SystemStoreImpl>();
    case StoreType::PeFile:
        return std::make_shared<Win32PeFileStore>();
    case StoreType::AppxFile:
        return std::make_shared<Win32AppxFileStore>();
    case StoreType::PfxFile:
        return std::make_shared<Win32PfxCertStore>();
    case StoreType::P7bFile:
        return std::make_shared<Win32P7bFileStore>();
    case StoreType::CerFile:
    default:
        break;
    }

    switch (FileTypeDetector::detectFileType(location))
    {
    case StoreType::PeFile:
        return std::make_shared<Win32PeFileStore>();
    case StoreType::AppxFile:
        return std::make_shared<Win32AppxFileStore>();
    case StoreType::PfxFile:
        return std::make_shared<Win32PfxCertStore>();
    case StoreType::P7bFile:
        return std::make_shared<Win32P7bFileStore>();
    case StoreType::CerFile:
    default:
        return std::make_shared<Win32CerFileStore>();
    }
}

CertificatePtr CryptoFactory::createCertificateFromDer(const std::vector<uint8_t>& derBytes)
{
    CertContextPtr certPtr(CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (certPtr == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<Win32Cert>(std::move(certPtr));
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    CrlContextPtr crlPtr(CertCreateCRLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (crlPtr == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<Win32Crl>(std::move(crlPtr));
}

CtlPtr CryptoFactory::createCtlFromDer(const std::vector<uint8_t>& derBytes)
{
    CtlContextPtr ctlPtr(CertCreateCTLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (ctlPtr == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<Win32Ctl>(std::move(ctlPtr));
}

DigestPtr CryptoFactory::getDigestFromName(const std::string& name)
{
    std::wstring wName = Win32Helper::utf8ToWide(Strings::toUpper(name));
    PCCRYPT_OID_INFO pInfo =
        CryptFindOIDInfo(CRYPT_OID_INFO_NAME_KEY, wName.data(), CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr)
    {
        return nullptr;
    }
    if (pInfo->Algid == CALG_OID_INFO_CNG_ONLY)
    {
        if (pInfo->pwszCNGAlgid == nullptr)
        {
            return nullptr;
        }
        return std::make_shared<Win32CngDigest>(pInfo->Algid, pInfo->pwszCNGAlgid);
    }
    if (pInfo->Algid == 0)
    {
        return nullptr;
    }
    return std::make_shared<Win32Digest>(pInfo->Algid);
}

DigestPtr CryptoFactory::getDigestFromOid(const std::string& oid)
{
    std::string tempOid = oid;
    PCCRYPT_OID_INFO pInfo =
        CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, tempOid.data(), CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr)
    {
        return nullptr;
    }
    if (pInfo->Algid == CALG_OID_INFO_CNG_ONLY)
    {
        if (pInfo->pwszCNGAlgid == nullptr)
        {
            return nullptr;
        }
        return std::make_shared<Win32CngDigest>(pInfo->Algid, pInfo->pwszCNGAlgid);
    }
    if (pInfo->Algid == 0)
    {
        return nullptr;
    }
    return std::make_shared<Win32Digest>(pInfo->Algid);
}

bool CryptoFactory::acquireContext(const std::string& container, const std::string& provider)
{
    std::wstring wContainer = Win32Helper::utf8ToWide(container);
    std::wstring wProvider = Win32Helper::utf8ToWide(provider);

    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, wContainer.empty() ? nullptr : wContainer.c_str(),
            wProvider.empty() ? nullptr : wProvider.c_str(), PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptReleaseContext(hProv, 0);
        return true;
    }
    return false;
}

void CryptoFactory::deleteKeyContainer(
    const std::string& name, const std::string& provider, uint32_t providerType)
{
    std::wstring wName = Win32Helper::utf8ToWide(name);
    std::wstring wProvider = Win32Helper::utf8ToWide(provider);
    HCRYPTPROV hProv = 0;
    CryptAcquireContextW(&hProv, wName.empty() ? nullptr : wName.c_str(),
        wProvider.empty() ? nullptr : wProvider.c_str(),
        providerType == 0 ? PROV_RSA_FULL : providerType, CRYPT_DELETEKEYSET);
}

std::vector<uint8_t> CryptoFactory::encryptRc4Bytes(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    CryptProvPtr hProv;
    if (!CryptAcquireContextW(&hProv.init(), nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        throw CckyException("Failed to acquire crypt context for RC4");
    }

    // Prepare PLAINTEXTKEYBLOB
    std::vector<uint8_t> blobBuf(sizeof(BLOBHEADER) + sizeof(DWORD) + key.size());
    BLOBHEADER* hdr = reinterpret_cast<BLOBHEADER*>(blobBuf.data());
    hdr->bType = PLAINTEXTKEYBLOB;
    hdr->bVersion = CUR_BLOB_VERSION;
    hdr->reserved = 0;
    hdr->aiKeyAlg = CALG_RC4;

    DWORD* keySize = reinterpret_cast<DWORD*>(blobBuf.data() + sizeof(BLOBHEADER));
    *keySize = static_cast<DWORD>(key.size());

    std::copy(key.begin(), key.end(), blobBuf.begin() + sizeof(BLOBHEADER) + sizeof(DWORD));

    CryptKeyPtr hKey;
    if (!CryptImportKey(
            hProv.get(), blobBuf.data(), static_cast<DWORD>(blobBuf.size()), 0, 0, &hKey.init()))
    {
        throw CckyException("Failed to import RC4 key");
    }

    std::vector<uint8_t> out = data;
    DWORD dataLen = static_cast<DWORD>(out.size());
    DWORD bufLen = dataLen;
    if (!CryptEncrypt(hKey.get(), 0, TRUE, 0, out.data(), &dataLen, bufLen))
    {
        throw CckyException("Failed to encrypt/decrypt with RC4");
    }
    return out;
}

void CryptoFactory::getRandomBytes(void* buf, size_t len)
{
    CryptProvPtr hProv;
    if (!CryptAcquireContextW(&hProv.init(), nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        throw CckyException("Failed to acquire crypt context for random bytes");
    }

    if (!CryptGenRandom(hProv.get(), static_cast<DWORD>(len), static_cast<BYTE*>(buf)))
    {
        throw CckyException("Failed to generate random bytes");
    }
}

} // namespace crypto
} // namespace ccky
