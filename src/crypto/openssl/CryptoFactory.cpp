#include "crypto/CryptoFactory.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "crypto/openssl/OpenSslCert.h"
#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/OpenSslStore.h"

namespace ccky
{
namespace crypto
{

const std::string& CryptoFactory::getBackendType()
{
    static const std::string s_backend = "openssl";
    return s_backend;
}

std::shared_ptr<ICertStore> CryptoFactory::createStore(StoreType type, const std::string& location)
{
    if (type == StoreType::WinSystem)
    {
        return std::make_shared<OpenSslWinSystemStore>();
    }
    if (type == StoreType::PeFile)
    {
        return std::make_shared<OpenSslPeFileStore>();
    }
    if (type == StoreType::PfxFile)
    {
        return std::make_shared<OpenSslPfxCertStore>();
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
                    return std::make_shared<OpenSslPeFileStore>();
                }
            }
        }
        file.close();
    }

    BIOPtr bio(BIO_new_file(location.c_str(), "rb"));
    if (bio)
    {
        PKCS12* p12 = d2i_PKCS12_bio(bio.get(), nullptr);
        if (p12)
        {
            PKCS12_free(p12);
            return std::make_shared<OpenSslPfxCertStore>();
        }
    }

    return std::make_shared<OpenSslCerFileStore>();
}

CertificatePtr CryptoFactory::createCertificateFromDer(const std::vector<uint8_t>& derBytes)
{
    const unsigned char* p = derBytes.data();
    X509* x = d2i_X509(nullptr, &p, derBytes.size());
    if (!x)
    {
        return nullptr;
    }
    auto res = std::make_shared<OpenSslCert>(x);
    X509_free(x);
    return res;
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    const unsigned char* p = derBytes.data();
    X509_CRL* x = d2i_X509_CRL(nullptr, &p, derBytes.size());
    if (!x)
    {
        return nullptr;
    }
    auto res = std::make_shared<OpenSslCrl>(x);
    X509_CRL_free(x);
    return res;
}

CtlPtr CryptoFactory::createCtlFromDer(const std::vector<uint8_t>& derBytes)
{
    return std::make_shared<OpenSslCtl>(derBytes);
}

bool CryptoFactory::acquireContext(const std::string& container, const std::string& provider)
{
    throw OpenSslException("Windows Cryptographic Service Providers are unsupported on this "
                           "platform (OpenSSL backend).",
        false);
}

std::string CryptoFactory::calculateSha256(const std::string& filePath)
{
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open())
    {
        return "";
    }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return OpenSslHelper::getBufferSha256(data);
}

} // namespace crypto
} // namespace ccky
