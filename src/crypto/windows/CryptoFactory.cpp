#include "crypto/CryptoFactory.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <windows.h>

#include <wincrypt.h>

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
    if (type == StoreType::PfxFile)
    {
        return std::make_shared<WinPfxCertStore>();
    }

    std::ifstream file(location, std::ios::binary);
    if (file.is_open())
    {
        char mz[2];
        if (file.read(mz, 2) && mz[0] == 'M' && mz[1] == 'Z')
        {
            file.seekg(0x3C, std::ios::beg);
            uint32_t peOffset = 0;
            if (file.read(reinterpret_cast<char*>(&peOffset), 4))
            {
                file.seekg(peOffset, std::ios::beg);
                char pe[4];
                if (file.read(pe, 4) && pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' &&
                    pe[3] == '\0')
                {
                    file.close();
                    return std::make_shared<WinPeFileStore>();
                }
            }
        }
        file.close();
    }

    std::wstring wLocation = WinHelper::utf8ToWide(location);
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wLocation.c_str(), CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore,
            &hMsg, nullptr))
    {
        if (hStore)
        {
            CertCloseStore(hStore, 0);
        }
        if (hMsg)
        {
            CryptMsgClose(hMsg);
        }

        if (dwContentType == CERT_QUERY_CONTENT_PFX)
        {
            return std::make_shared<WinPfxCertStore>();
        }
    }

    return std::make_shared<WinCerFileStore>();
}

CertificatePtr CryptoFactory::createCertificateFromDer(const std::vector<uint8_t>& derBytes)
{
    PCCERT_CONTEXT pCert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size());
    if (!pCert)
    {
        return nullptr;
    }
    auto res = std::make_shared<WinCert>(pCert);
    CertFreeCertificateContext(pCert);
    return res;
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    PCCRL_CONTEXT pCrl = CertCreateCRLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size());
    if (!pCrl)
    {
        return nullptr;
    }
    auto res = std::make_shared<WinCrl>(pCrl);
    CertFreeCRLContext(pCrl);
    return res;
}

CtlPtr CryptoFactory::createCtlFromDer(const std::vector<uint8_t>& derBytes)
{
    PCCTL_CONTEXT pCtl = CertCreateCTLContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBytes.data(), derBytes.size());
    if (!pCtl)
    {
        return nullptr;
    }
    auto res = std::make_shared<WinCtl>(pCtl);
    CertFreeCTLContext(pCtl);
    return res;
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

} // namespace crypto
} // namespace ccky
