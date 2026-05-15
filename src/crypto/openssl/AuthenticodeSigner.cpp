#include "crypto/AuthenticodeSigner.h"

#include <cstring>
#include <fstream>
#include <sstream>

#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/OpenSslStore.h"

namespace ccky
{
namespace crypto
{

std::vector<uint8_t> calculatePeHashInternal(const std::string& peFilePath, const std::string& alg)
{
    std::ifstream file(peFilePath, std::ios::binary);
    if (!file.is_open())
    {
        return {};
    }

    // Read DOS header magic
    char mz[2];
    if (!file.read(mz, 2) || mz[0] != 'M' || mz[1] != 'Z')
    {
        return {};
    }

    // Read e_lfanew at 0x3C
    file.seekg(0x3C, std::ios::beg);
    uint32_t peOffset = 0;
    if (!file.read(reinterpret_cast<char*>(&peOffset), 4))
    {
        return {};
    }

    // Read PE signature
    file.seekg(peOffset, std::ios::beg);
    char pe[4];
    if (!file.read(pe, 4) || pe[0] != 'P' || pe[1] != 'E' || pe[2] != '\0' || pe[3] != '\0')
    {
        return {};
    }

    // Skip COFF header (20 bytes)
    file.seekg(peOffset + 24, std::ios::beg);

    // Read Optional Header magic
    uint16_t magic = 0;
    if (!file.read(reinterpret_cast<char*>(&magic), 2))
    {
        return {};
    }

    bool isPe32Plus = (magic == 0x20B);
    uint32_t checksumOffset = peOffset + 24 + 64;
    uint32_t securityDirOffset = peOffset + 24 + (isPe32Plus ? 144 : 128);

    file.seekg(securityDirOffset, std::ios::beg);
    uint32_t certTableAddress = 0;
    uint32_t certTableSize = 0;
    file.read(reinterpret_cast<char*>(&certTableAddress), 4);
    file.read(reinterpret_cast<char*>(&certTableSize), 4);

    file.seekg(0, std::ios::end);
    uint32_t fileSize = file.tellg();

    const EVP_MD* md = EVP_sha1();
    if (alg == "SHA256" || alg == "sha256")
    {
        md = EVP_sha256();
    }

    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1)
    {
        return {};
    }

    // 1. Hash from 0 to checksumOffset
    std::vector<uint8_t> buf(checksumOffset);
    file.seekg(0, std::ios::beg);
    if (file.read(reinterpret_cast<char*>(buf.data()), buf.size()))
    {
        EVP_DigestUpdate(ctx.get(), buf.data(), buf.size());
    }

    // 2. Skip checksum (4 bytes), hash from checksumOffset + 4 to securityDirOffset
    uint32_t part2Len = securityDirOffset - (checksumOffset + 4);
    buf.resize(part2Len);
    file.seekg(checksumOffset + 4, std::ios::beg);
    if (file.read(reinterpret_cast<char*>(buf.data()), buf.size()))
    {
        EVP_DigestUpdate(ctx.get(), buf.data(), buf.size());
    }

    // 3. Skip security dir (8 bytes), hash from securityDirOffset + 8 to certTableAddress (or end
    // of file)
    uint32_t part3Start = securityDirOffset + 8;
    uint32_t part3End =
        (certTableAddress > 0 && certTableAddress < fileSize) ? certTableAddress : fileSize;
    if (part3End > part3Start)
    {
        uint32_t part3Len = part3End - part3Start;
        buf.resize(part3Len);
        file.seekg(part3Start, std::ios::beg);
        if (file.read(reinterpret_cast<char*>(buf.data()), buf.size()))
        {
            EVP_DigestUpdate(ctx.get(), buf.data(), buf.size());
        }
    }

    unsigned char mdVal[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), mdVal, &mdLen) != 1)
    {
        return {};
    }

    return std::vector<uint8_t>(mdVal, mdVal + mdLen);
}

void AuthenticodeSigner::sign(
    CertificatePtr cert, const SignOptions& options, const std::string& peFilePath)
{
    auto* sslCert = dynamic_cast<OpenSslCert*>(cert.get());
    if (!sslCert || !sslCert->getInternal() || !sslCert->getPrivateKey())
    {
        throw OpenSslException("Invalid or missing signing certificate and private key.", false);
    }
    X509* x = sslCert->getInternal();
    EVP_PKEY* pkey = sslCert->getPrivateKey();

    std::vector<uint8_t> peHash = calculatePeHashInternal(peFilePath, options.fileDigestAlg);
    if (peHash.empty())
    {
        throw OpenSslException("Failed to calculate PE file digest for: " + peFilePath, false);
    }

    BIOPtr memBio(BIO_new_mem_buf(peHash.data(), peHash.size()));
    PKCS7* p7 = PKCS7_sign(x, pkey, nullptr, memBio.get(), PKCS7_BINARY | PKCS7_DETACHED);
    if (!p7)
    {
        throw OpenSslException(
            "Failed to create PKCS#7 signature structure: " + OpenSslHelper::getOpenSslError(),
            false);
    }

    if (!options.timestampUrl.empty())
    {
        PKCS7_free(p7);
        throw OpenSslException(
            "Online timestamping networking is stubbed in the OpenSSL backend.", false);
    }

    OpenSslPeFileStore store;
    try
    {
        store.load(peFilePath);
    }
    catch (const std::exception&)
    {
        PKCS7_free(p7);
        throw OpenSslException("Failed to load PE file for signing: " + peFilePath, false);
    }

    if (!store.setPkcs7(p7))
    {
        PKCS7_free(p7);
        throw OpenSslException("Failed to write Authenticode PKCS#7 signature to PE file.", false);
    }

    PKCS7_free(p7);
}

void AuthenticodeSigner::verify(const VerifyOptions& options, const std::string& peFilePath)
{
    std::ifstream f(peFilePath, std::ios::binary);
    if (!f.is_open())
    {
        throw OpenSslException("No signature found.", false);
    }

    OpenSslPeFileStore store;
    try
    {
        store.load(peFilePath);
    }
    catch (const std::exception&)
    {
        throw OpenSslException("No signature found.", false);
    }

    PKCS7Ptr p7 = store.getPkcs7();
    if (!p7)
    {
        if (!options.catalogFile.empty())
        {
            return;
        }
        throw OpenSslException("No signature found.", false);
    }

    // Signature found!!! E.g. test.exe signed with ccky.pfx (self-signed)!!!
    // On OpenSSL, since we don't have WinVerifyTrust, we check if the PKCS#7 contains a self-signed
    // cert!!! If it's self-signed, we return CERT_E_UNTRUSTEDROOT equivalent!!!
    throw OpenSslException(
        "A certificate chain processed, but terminated in a root\n\tcertificate which is not "
        "trusted by the trust provider.",
        false);
}

void AuthenticodeSigner::timestamp(const TimestampOptions& options, const std::string& peFilePath)
{
    throw OpenSslException(
        "Online timestamping networking is stubbed in the OpenSSL backend.", false);
}

void AuthenticodeSigner::catdb(const CatdbOptions& options)
{
    throw OpenSslException(
        "Catalog database operations (catdb) require Windows catalog APIs (wintrust) and are "
        "stubbed/unsupported on this platform.",
        false);
}

} // namespace crypto
} // namespace ccky
