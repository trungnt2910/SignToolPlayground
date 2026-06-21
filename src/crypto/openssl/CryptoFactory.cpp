#include "crypto/CryptoFactory.h"

#include <fstream>
#include <stdexcept>

#include "crypto/FileTypeDetector.h"
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
    if (type == StoreType::AppxFile)
    {
        return std::make_shared<OpenSslAppxFileStore>();
    }
    if (type == StoreType::PfxFile)
    {
        return std::make_shared<OpenSslPfxCertStore>();
    }

    StoreType detected = FileTypeDetector::detectFileType(location);
    if (detected == StoreType::PeFile)
    {
        return std::make_shared<OpenSslPeFileStore>();
    }
    if (detected == StoreType::AppxFile)
    {
        return std::make_shared<OpenSslAppxFileStore>();
    }
    if (detected == StoreType::PfxFile)
    {
        return std::make_shared<OpenSslPfxCertStore>();
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
