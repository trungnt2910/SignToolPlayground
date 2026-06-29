#include "crypto/CryptoFactory.h"

#include <fstream>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto/FileTypeDetector.h"
#include "crypto/openssl/OpenSslCert.h"
#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/OpenSslHelper.h"
#include "crypto/openssl/OpenSslStore.h"
#include "crypto/openssl/OpenSslWrapper.h"

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
    X509Ptr x(d2i_X509(nullptr, &p, derBytes.size()));
    if (!x)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslCert>(x.get());
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    const unsigned char* p = derBytes.data();
    X509CRLPtr x(d2i_X509_CRL(nullptr, &p, derBytes.size()));
    if (!x)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslCrl>(x.get());
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

void CryptoFactory::deleteKeyContainer(
    const std::string& name, const std::string& provider, uint32_t providerType)
{
    // No-op on non-Windows platforms
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

std::vector<uint8_t> CryptoFactory::calculateSha1Bytes(const std::vector<uint8_t>& data)
{
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
    {
        throw OpenSslException("Failed to create MD context");
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
    {
        throw OpenSslException("Failed to compute SHA1");
    }

    uint8_t digest[20];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &len) != 1)
    {
        throw OpenSslException("Failed to finalize SHA1");
    }

    return std::vector<uint8_t>(digest, digest + 20);
}

// We implement a custom RC4 function here instead of using OpenSSL's EVP_rc4()
// because RC4 is deprecated in OpenSSL 3.0 and moved to the legacy provider.
// The legacy provider is not loaded by default and might not be installed
// on the host system, which would cause runtime failures.
std::vector<uint8_t> CryptoFactory::encryptRc4Bytes(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> out = data;
    uint8_t S[256];
    for (int i = 0; i < 256; i++)
    {
        S[i] = i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }
    int i = 0;
    j = 0;
    for (size_t n = 0; n < out.size(); n++)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        out[n] ^= S[(S[i] + S[j]) % 256];
    }
    return out;
}

void CryptoFactory::getRandomBytes(void* buf, size_t len)
{
    if (RAND_bytes(static_cast<unsigned char*>(buf), static_cast<int>(len)) != 1)
    {
        throw OpenSslException("Failed to generate random bytes");
    }
}

} // namespace crypto
} // namespace ccky
