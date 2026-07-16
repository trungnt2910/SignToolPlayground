#include "crypto/CryptoFactory.h"

#include <fstream>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto/FileTypeDetector.h"
#include "crypto/openssl/OpenSslCert.h"
#include "crypto/openssl/OpenSslDigest.h"
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

CertificateStorePtr CryptoFactory::createStore(StoreType type, const std::string& location)
{
    switch (type)
    {
    case StoreType::WinSystem:
        return std::make_shared<OpenSslWinSystemStore>();
    case StoreType::PeFile:
        return std::make_shared<OpenSslPeFileStore>();
    case StoreType::AppxFile:
        return std::make_shared<OpenSslAppxFileStore>();
    case StoreType::PfxFile:
        return std::make_shared<OpenSslPfxCertStore>();
    case StoreType::P7bFile:
        return std::make_shared<OpenSslP7bFileStore>();
    case StoreType::CerFile:
    default:
        break;
    }

    switch (FileTypeDetector::detectFileType(location))
    {
    case StoreType::PeFile:
        return std::make_shared<OpenSslPeFileStore>();
    case StoreType::AppxFile:
        return std::make_shared<OpenSslAppxFileStore>();
    case StoreType::PfxFile:
        return std::make_shared<OpenSslPfxCertStore>();
    case StoreType::P7bFile:
        return std::make_shared<OpenSslP7bFileStore>();
    case StoreType::CerFile:
    default:
        return std::make_shared<OpenSslCerFileStore>();
    }
}

CertificatePtr CryptoFactory::createCertificateFromDer(const std::vector<uint8_t>& derBytes)
{
    const unsigned char* p = derBytes.data();
    X509Ptr x(d2i_X509(nullptr, &p, derBytes.size()));
    if (x == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslCert>(std::move(x));
}

CrlPtr CryptoFactory::createCrlFromDer(const std::vector<uint8_t>& derBytes)
{
    const unsigned char* p = derBytes.data();
    X509CRLPtr x(d2i_X509_CRL(nullptr, &p, derBytes.size()));
    if (x == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslCrl>(std::move(x));
}

CtlPtr CryptoFactory::createCtlFromDer(const std::vector<uint8_t>& derBytes)
{
    return std::make_shared<OpenSslCtl>(derBytes);
}

DigestPtr CryptoFactory::getDigestFromName(const std::string& name)
{
    const EVP_MD* md = EVP_get_digestbyname(name.c_str());
    if (!md)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslDigest>(EVP_MD_type(md));
}

DigestPtr CryptoFactory::getDigestFromOid(const std::string& oid)
{
    ASN1ObjectPtr obj(OBJ_txt2obj(oid.c_str(), /* no_name = */ 1));
    if (obj == nullptr)
    {
        return nullptr;
    }
    int nid = OBJ_obj2nid(obj.get());
    if (nid == NID_undef)
    {
        return nullptr;
    }
    const EVP_MD* md = EVP_get_digestbynid(nid);
    if (!md)
    {
        return nullptr;
    }
    return std::make_shared<OpenSslDigest>(nid);
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
    OpenSslCheck::check(RAND_bytes(static_cast<unsigned char*>(buf), static_cast<int>(len)) == 1,
        "Failed to generate random bytes");
}

} // namespace crypto
} // namespace ccky
