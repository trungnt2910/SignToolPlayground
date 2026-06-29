#include "crypto/AuthenticodeSigner.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <pugixml.hpp>

#include "crypto/CryptoFactory.h"
#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/OpenSslHelper.h"
#include "crypto/openssl/OpenSslStore.h"
#include "crypto/openssl/ZipArchive.h"

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

    const EVP_MD* md = OpenSslHelper::getDigestAlgorithm(alg);

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

std::vector<uint8_t> calculateAppxHashInternal(const std::string& filePath, const std::string& alg)
{
    try
    {
        ZipArchive archive(filePath);
        const EVP_MD* md = OpenSslHelper::getDigestAlgorithm(alg);

        auto hashBuf = [&](const std::vector<uint8_t>& data) -> std::vector<uint8_t>
        {
            EVPMDCtxPtr ctx(EVP_MD_CTX_new());
            if (!ctx || EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1)
            {
                return {};
            }
            EVP_DigestUpdate(ctx.get(), data.data(), data.size());
            unsigned char val[EVP_MAX_MD_SIZE];
            unsigned int len = 0;
            if (EVP_DigestFinal_ex(ctx.get(), val, &len) != 1)
            {
                return {};
            }
            return std::vector<uint8_t>(val, val + len);
        };

        auto ctBytes = archive.getUncompressedContent("[Content_Types].xml");
        pugi::xml_document doc;
        if (doc.load_buffer(
                ctBytes.data(), ctBytes.size(), pugi::parse_default | pugi::parse_declaration))
        {
            pugi::xml_node typesNode = doc.child("Types");
            if (typesNode)
            {
                bool found = false;
                for (pugi::xml_node node = typesNode.child("Override"); node;
                    node = node.next_sibling("Override"))
                {
                    if (std::string(node.attribute("PartName").value()) == "/AppxSignature.p7x")
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    pugi::xml_node overrideNode = typesNode.append_child("Override");
                    overrideNode.append_attribute("PartName") = "/AppxSignature.p7x";
                    overrideNode.append_attribute("ContentType") =
                        "application/vnd.ms-appx.signature";

                    struct XmlWriter : pugi::xml_writer
                    {
                        std::vector<uint8_t> buf;
                        void write(const void* data, size_t size) override
                        {
                            const auto* p = static_cast<const uint8_t*>(data);
                            buf.insert(buf.end(), p, p + size);
                        }
                    } writer;

                    doc.save(writer, "", pugi::format_raw);
                    archive.setEntryContent("[Content_Types].xml", writer.buf, true);
                }
            }
        }

        archive.save(filePath);
        ZipArchive updatedArchive(filePath);

        EVPMDCtxPtr axpcCtx(EVP_MD_CTX_new());
        EVP_DigestInit_ex(axpcCtx.get(), md, nullptr);
        for (const auto& name : updatedArchive.getEntryOrder())
        {
            if (name == "AppxSignature.p7x")
            {
                break;
            }
            const auto* e = updatedArchive.getEntry(name);
            if (e)
            {
                EVP_DigestUpdate(axpcCtx.get(), e->rawBytes.data(), e->rawBytes.size());
            }
        }
        unsigned char axpcVal[EVP_MAX_MD_SIZE];
        unsigned int axpcLen = 0;
        EVP_DigestFinal_ex(axpcCtx.get(), axpcVal, &axpcLen);

        std::vector<uint8_t> cdBuf;
        uint32_t currOff = 0;
        for (const auto& name : updatedArchive.getEntryOrder())
        {
            const auto* e = updatedArchive.getEntry(name);
            if (!e)
            {
                continue;
            }
            if (name == "AppxSignature.p7x")
            {
                continue;
            }
            ZipSerializer::serializeCentralDirHeader(cdBuf, *e, name, currOff);
            currOff += static_cast<uint32_t>(e->rawBytes.size());
        }
        auto axcdDig = hashBuf(cdBuf);
        auto axctDig = hashBuf(updatedArchive.getUncompressedContent("[Content_Types].xml"));
        auto axbmDig = hashBuf(updatedArchive.getUncompressedContent("AppxBlockMap.xml"));

        std::vector<uint8_t> out;
        auto appendStr = [&](const char* s) { out.insert(out.end(), s, s + 4); };
        auto appendDig = [&](const unsigned char* d, unsigned int l)
        { out.insert(out.end(), d, d + l); };
        auto appendVec = [&](const std::vector<uint8_t>& v)
        { out.insert(out.end(), v.begin(), v.end()); };

        appendStr("APPX");
        appendStr("AXPC");
        appendDig(axpcVal, axpcLen);
        appendStr("AXCD");
        appendVec(axcdDig);
        appendStr("AXCT");
        appendVec(axctDig);
        appendStr("AXBM");
        appendVec(axbmDig);

        if (updatedArchive.hasEntry("AppxMetadata/CodeIntegrity.cat"))
        {
            auto axciDig =
                hashBuf(updatedArchive.getUncompressedContent("AppxMetadata/CodeIntegrity.cat"));
            appendStr("AXCI");
            appendVec(axciDig);
        }

        return out;
    }
    catch (...)
    {
        return {};
    }
}

namespace
{
void signAppx(X509* x, EVP_PKEY* pkey, const SignOptions& options, const std::string& filePath,
    ICertStore* store)
{
    std::vector<uint8_t> appxHash = calculateAppxHashInternal(filePath, options.fileDigestAlg);
    if (appxHash.empty())
    {
        throw OpenSslException("Failed to calculate APPX file digest for: " + filePath, false);
    }
    BIOPtr memBio(BIO_new_mem_buf(appxHash.data(), appxHash.size()));
    PKCS7Ptr p7(PKCS7_sign(x, pkey, nullptr, memBio.get(), PKCS7_BINARY | PKCS7_DETACHED));
    if (!p7)
    {
        throw OpenSslException("Failed to create PKCS#7 signature structure", false);
    }
    auto* appxStore = dynamic_cast<OpenSslAppxFileStore*>(store);
    if (!appxStore || !appxStore->setPkcs7(p7.get()))
    {
        throw OpenSslException(
            "Failed to write Authenticode PKCS#7 signature to APPX file.", false);
    }
}

void signPe(X509* x, EVP_PKEY* pkey, const SignOptions& options, const std::string& filePath,
    ICertStore* store)
{
    std::vector<uint8_t> peHash = calculatePeHashInternal(filePath, options.fileDigestAlg);
    if (peHash.empty())
    {
        throw OpenSslException("Failed to calculate PE file digest for: " + filePath, false);
    }
    BIOPtr memBio(BIO_new_mem_buf(peHash.data(), peHash.size()));
    PKCS7Ptr p7(PKCS7_sign(x, pkey, nullptr, memBio.get(), PKCS7_BINARY | PKCS7_DETACHED));
    if (!p7)
    {
        throw OpenSslException("Failed to create PKCS#7 signature structure", false);
    }
    auto* peStore = dynamic_cast<OpenSslPeFileStore*>(store);
    if (!peStore || !peStore->setPkcs7(p7.get()))
    {
        throw OpenSslException("Failed to write Authenticode PKCS#7 signature to PE file.", false);
    }
}
} // namespace

void AuthenticodeSigner::sign(
    CertificatePtr cert, const SignOptions& options, const std::string& filePath)
{
    auto* sslCert = dynamic_cast<OpenSslCert*>(cert.get());
    if (!sslCert || !sslCert->getInternal() || !sslCert->getPrivateKey())
    {
        throw OpenSslException("Invalid or missing signing certificate and private key.", false);
    }
    X509* x = sslCert->getInternal();
    EVP_PKEY* pkey = sslCert->getPrivateKey();

    if (!options.timestampUrl.empty())
    {
        throw OpenSslException(
            "Online timestamping networking is stubbed in the OpenSSL backend.", false);
    }

    auto store = CryptoFactory::createStore(StoreType::CerFile, filePath);
    StoreOptions opts;
    store->load(filePath, opts);

    if (store->getStoreType() == StoreType::AppxFile)
    {
        signAppx(x, pkey, options, filePath, store.get());
    }
    else if (store->getStoreType() == StoreType::PeFile)
    {
        signPe(x, pkey, options, filePath, store.get());
    }
    else
    {
        throw OpenSslException(
            "Unsupported file format for Authenticode signing: " + filePath, false);
    }
}

void AuthenticodeSigner::verify(const VerifyOptions& options, const std::string& filePath)
{
    if (!std::filesystem::exists(filePath))
    {
        throw OpenSslException("No signature found.", false);
    }

    auto store = CryptoFactory::createStore(StoreType::CerFile, filePath);
    StoreOptions opts;
    try
    {
        store->load(filePath, opts);
    }
    catch (const std::exception&)
    {
        throw OpenSslException("No signature found.", false);
    }

    if (store->getCertificates().empty())
    {
        if (!options.catalogFile.empty())
        {
            return;
        }
        throw OpenSslException("No signature found.", false);
    }

    // Signature found. E.g. test.exe signed with ccky.pfx (self-signed).
    // On OpenSSL, since we don't have WinVerifyTrust, we check if the PKCS#7 contains a self-signed
    // cert. If it's self-signed, we return CERT_E_UNTRUSTEDROOT equivalent.
    throw OpenSslException(
        "A certificate chain processed, but terminated in a root\n\tcertificate which is not "
        "trusted by the trust provider.",
        false);
}

void AuthenticodeSigner::timestamp(const TimestampOptions& options, const std::string& filePath)
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
