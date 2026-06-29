#include "crypto/CryptoFactory.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <windows.h>

#include <wincrypt.h>

#include "crypto/CckyException.h"
#include "crypto/FileTypeDetector.h"
#include "crypto/windows/WinCert.h"
#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WinStore.h"
#include "crypto/windows/WinWrapper.h"

namespace ccky
{
namespace crypto
{

const std::string& CryptoFactory::getBackendType()
{
    static const std::string s_backend = "windows";
    return s_backend;
}

std::shared_ptr<ICertStore> CryptoFactory::createStore(StoreType type, const std::string& location)
{
    if (type == StoreType::WinSystem)
    {
        return std::make_shared<WinSystemStoreImpl>();
    }
    if (type == StoreType::PeFile)
    {
        return std::make_shared<WinPeFileStore>();
    }
    if (type == StoreType::AppxFile)
    {
        return std::make_shared<WinAppxFileStore>();
    }
    if (type == StoreType::PfxFile)
    {
        return std::make_shared<WinPfxCertStore>();
    }

    StoreType detected = FileTypeDetector::detectFileType(location);
    if (detected == StoreType::PeFile)
    {
        return std::make_shared<WinPeFileStore>();
    }
    if (detected == StoreType::AppxFile)
    {
        return std::make_shared<WinAppxFileStore>();
    }
    if (detected == StoreType::PfxFile)
    {
        return std::make_shared<WinPfxCertStore>();
    }
    return std::make_shared<WinCerFileStore>();
}

CertificatePtr CryptoFactory::createCertificateFromDer(const std::vector<uint8_t>& derBytes)
{
    CertContextPtr certPtr(CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (!certPtr)
    {
        return nullptr;
    }
    return std::make_shared<WinCert>(certPtr.get());
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    CrlContextPtr crlPtr(CertCreateCRLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (!crlPtr)
    {
        return nullptr;
    }
    return std::make_shared<WinCrl>(crlPtr.get());
}

CtlPtr CryptoFactory::createCtlFromDer(const std::vector<uint8_t>& derBytes)
{
    CtlContextPtr ctlPtr(CertCreateCTLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size()));
    if (!ctlPtr)
    {
        return nullptr;
    }
    return std::make_shared<WinCtl>(ctlPtr.get());
}

bool CryptoFactory::acquireContext(const std::string& container, const std::string& provider)
{
    std::wstring wContainer = WinHelper::utf8ToWide(container);
    std::wstring wProvider = WinHelper::utf8ToWide(provider);

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
    std::wstring wName = WinHelper::utf8ToWide(name);
    std::wstring wProvider = WinHelper::utf8ToWide(provider);
    HCRYPTPROV hProv = 0;
    CryptAcquireContextW(&hProv, wName.empty() ? nullptr : wName.c_str(),
        wProvider.empty() ? nullptr : wProvider.c_str(),
        providerType == 0 ? PROV_RSA_FULL : providerType, CRYPT_DELETEKEYSET);
}

std::string CryptoFactory::calculateSha256(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        return "";
    }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.empty())
    {
        return "";
    }

    HCRYPTPROV rawProv = 0;
    if (CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CryptProvPtr hProv(rawProv);
        HCRYPTHASH rawHash = 0;
        if (CryptCreateHash(hProv.get(), CALG_SHA_256, 0, 0, &rawHash))
        {
            CryptHashPtr hHash(rawHash);
            if (CryptHashData(hHash.get(), data.data(), data.size(), 0))
            {
                BYTE hash[32];
                DWORD len = sizeof(hash);
                if (CryptGetHashParam(hHash.get(), HP_HASHVAL, hash, &len, 0))
                {
                    std::stringstream ss;
                    for (DWORD i = 0; i < len; ++i)
                    {
                        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                           << static_cast<int>(hash[i]);
                    }
                    return ss.str();
                }
            }
        }
    }
    return "";
}

std::vector<uint8_t> CryptoFactory::calculateSha1Bytes(const std::vector<uint8_t>& data)
{
    HCRYPTPROV rawProv = 0;
    if (!CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        throw CckyException("Failed to acquire crypt context for SHA1");
    }
    CryptProvPtr hProv(rawProv);

    HCRYPTHASH rawHash = 0;
    if (!CryptCreateHash(hProv.get(), CALG_SHA1, 0, 0, &rawHash))
    {
        throw CckyException("Failed to create SHA1 hash");
    }
    CryptHashPtr hHash(rawHash);

    if (!CryptHashData(hHash.get(), data.data(), static_cast<DWORD>(data.size()), 0))
    {
        throw CckyException("Failed to hash data");
    }

    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (!CryptGetHashParam(hHash.get(), HP_HASHVAL, hash, &len, 0))
    {
        throw CckyException("Failed to get hash value");
    }

    return std::vector<uint8_t>(hash, hash + 20);
}

std::vector<uint8_t> CryptoFactory::encryptRc4Bytes(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    HCRYPTPROV rawProv = 0;
    if (!CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        throw CckyException("Failed to acquire crypt context for RC4");
    }
    CryptProvPtr hProv(rawProv);

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

    HCRYPTKEY rawKey = 0;
    if (!CryptImportKey(
            hProv.get(), blobBuf.data(), static_cast<DWORD>(blobBuf.size()), 0, 0, &rawKey))
    {
        throw CckyException("Failed to import RC4 key");
    }
    CryptKeyPtr hKey(rawKey);

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
    HCRYPTPROV rawProv = 0;
    if (!CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        throw CckyException("Failed to acquire crypt context for random bytes");
    }
    CryptProvPtr hProv(rawProv);

    if (!CryptGenRandom(hProv.get(), static_cast<DWORD>(len), static_cast<BYTE*>(buf)))
    {
        throw CckyException("Failed to generate random bytes");
    }
}

} // namespace crypto
} // namespace ccky
