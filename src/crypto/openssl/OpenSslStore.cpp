#include "crypto/openssl/OpenSslStore.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "crypto/AuthenticodeSigner.h"
#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/ZipArchive.h"

namespace ccky
{
namespace crypto
{

void OpenSslCerFileStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;

    BIOPtr bio(BIO_new_file(location.c_str(), "rb"));
    if (!bio)
    {
        return;
    }

    while (true)
    {
        X509* x = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!x)
        {
            break;
        }
        m_certs.push_back(X509Ptr(x));
    }

    if (m_certs.empty())
    {
        BIO_reset(bio.get());
        X509* x = d2i_X509_bio(bio.get(), nullptr);
        if (x)
        {
            m_certs.push_back(X509Ptr(x));
        }
    }

    if (m_certs.empty())
    {
        BIO_reset(bio.get());
        PKCS12* p12 = d2i_PKCS12_bio(bio.get(), nullptr);
        if (p12)
        {
            X509* c = nullptr;
            EVP_PKEY* k = nullptr;
            STACK_OF(X509)* ca = nullptr;
            if (PKCS12_parse(p12, "", &k, &c, &ca) == 1)
            {
                if (c)
                {
                    m_certs.push_back(X509Ptr(c));
                }
                if (k)
                {
                    EVP_PKEY_free(k);
                }
                if (ca)
                {
                    sk_X509_pop_free(ca, X509_free);
                }
            }
            PKCS12_free(p12);
        }
    }

    if (m_certs.empty())
    {
        BIO_reset(bio.get());
        PKCS7* p7 = PEM_read_bio_PKCS7(bio.get(), nullptr, nullptr, nullptr);
        if (!p7)
        {
            BIO_reset(bio.get());
            p7 = d2i_PKCS7_bio(bio.get(), nullptr);
        }
        if (p7)
        {
            if (PKCS7_type_is_signed(p7) && p7->d.sign && p7->d.sign->cert)
            {
                STACK_OF(X509)* sk = p7->d.sign->cert;
                for (int i = 0; i < sk_X509_num(sk); ++i)
                {
                    X509* x = sk_X509_value(sk, i);
                    m_certs.push_back(X509Ptr(X509_dup(x)));
                }
            }
            PKCS7_free(p7);
        }
    }

    BIO_reset(bio.get());
    while (true)
    {
        X509_CRL* c = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr);
        if (!c)
        {
            break;
        }
        m_crls.push_back(X509CRLPtr(c));
    }
    if (m_crls.empty())
    {
        BIO_reset(bio.get());
        X509_CRL* c = d2i_X509_CRL_bio(bio.get(), nullptr);
        if (c)
        {
            m_crls.push_back(X509CRLPtr(c));
        }
    }
}

void OpenSslCerFileStore::save(const std::string& location, const StoreOptions& options)
{
    BIOPtr bio(BIO_new_file(location.c_str(), "wb"));
    if (!bio)
    {
        throw OpenSslException("Failed to save the store", false);
    }

    for (const auto& cert : m_certs)
    {
        i2d_X509_bio(bio.get(), cert.get());
    }
    for (const auto& crl : m_crls)
    {
        i2d_X509_CRL_bio(bio.get(), crl.get());
    }
    for (const auto& ctl : m_ctls)
    {
        auto der = ctl->getEncoded();
        BIO_write(bio.get(), der.data(), der.size());
    }
}

bool OpenSslCerFileStore::saveAsPkcs7(const std::string& location)
{
    BIOPtr bio(BIO_new_file(location.c_str(), "wb"));
    if (!bio)
    {
        return false;
    }

    PKCS7* p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);

    for (const auto& cert : m_certs)
    {
        PKCS7_add_certificate(p7, cert.get());
    }
    for (const auto& crl : m_crls)
    {
        PKCS7_add_crl(p7, crl.get());
    }

    i2d_PKCS7_bio(bio.get(), p7);
    PKCS7_free(p7);
    return true;
}

std::vector<CertificatePtr> OpenSslCerFileStore::getCertificates()
{
    std::vector<CertificatePtr> list;
    for (const auto& c : m_certs)
    {
        list.push_back(std::make_shared<OpenSslCert>(c.get()));
    }
    return list;
}

std::vector<CrlPtr> OpenSslCerFileStore::getCrls()
{
    std::vector<CrlPtr> list;
    for (const auto& c : m_crls)
    {
        list.push_back(std::make_shared<OpenSslCrl>(c.get()));
    }
    return list;
}

std::vector<CtlPtr> OpenSslCerFileStore::getCtls() { return m_ctls; }

void OpenSslCerFileStore::addCertificate(CertificatePtr cert)
{
    if (!cert)
    {
        throw OpenSslException("Invalid certificate pointer", false);
    }
    auto der = cert->getEncoded();
    const unsigned char* p = der.data();
    X509* x = d2i_X509(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse certificate", false);
    }
    m_certs.push_back(X509Ptr(x));
}

void OpenSslCerFileStore::addCrl(CrlPtr crl)
{
    if (!crl)
    {
        throw OpenSslException("Invalid CRL pointer", false);
    }
    auto der = crl->getEncoded();
    const unsigned char* p = der.data();
    X509_CRL* x = d2i_X509_CRL(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse CRL", false);
    }
    m_crls.push_back(X509CRLPtr(x));
}

void OpenSslCerFileStore::addCtl(CtlPtr ctl)
{
    if (!ctl)
    {
        throw OpenSslException("Invalid CTL pointer", false);
    }
    m_ctls.push_back(ctl);
}

void OpenSslCerFileStore::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
{
    auto it = std::remove_if(m_certs.begin(), m_certs.end(),
        [&](const X509Ptr& c)
        {
            if (!commonName.empty() && OpenSslHelper::getCertCommonName(c.get()) != commonName)
            {
                return false;
            }
            if (!sha1Hash.empty() && OpenSslHelper::getCertSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_certs.erase(it, m_certs.end());
}

void OpenSslCerFileStore::deleteCrl(const std::string& sha1Hash)
{
    auto it = std::remove_if(m_crls.begin(), m_crls.end(),
        [&](const X509CRLPtr& c)
        {
            if (!sha1Hash.empty() && OpenSslHelper::getCrlSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_crls.erase(it, m_crls.end());
}

void OpenSslCerFileStore::deleteCtl(const std::string& sha1Hash)
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

void OpenSslCerFileStore::addPrivateKey(const std::string& pfxFilePath, const std::string& password)
{
    throw OpenSslException(
        "addPrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

void OpenSslCerFileStore::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "deletePrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

// PEFileStore
void OpenSslPeFileStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;
    m_securityDirOffset = 0;
    m_certTableAddress = 0;
    m_certTableSize = 0;
    m_isPe32Plus = false;
    m_signingAlgorithm = "sha256";
    m_timestamp = "None";

    std::ifstream file(location, std::ios::binary);
    if (!file.is_open())
    {
        throw OpenSslException("Failed to open the store", false);
    }

    char mz[2];
    if (!file.read(mz, 2) || mz[0] != 'M' || mz[1] != 'Z')
    {
        return;
    }

    file.seekg(0x3C, std::ios::beg);
    uint32_t peOffset = 0;
    if (!file.read(reinterpret_cast<char*>(&peOffset), 4))
    {
        return;
    }

    file.seekg(peOffset, std::ios::beg);
    char pe[4];
    if (!file.read(pe, 4) || pe[0] != 'P' || pe[1] != 'E' || pe[2] != '\0' || pe[3] != '\0')
    {
        return;
    }

    file.seekg(peOffset + 24, std::ios::beg);
    uint16_t magic = 0;
    if (!file.read(reinterpret_cast<char*>(&magic), 2))
    {
        return;
    }

    if (magic == 0x10B)
    {
        m_isPe32Plus = false;
        m_securityDirOffset = peOffset + 24 + 128;
    }
    else if (magic == 0x20B)
    {
        m_isPe32Plus = true;
        m_securityDirOffset = peOffset + 24 + 144;
    }
    else
    {
        return;
    }

    file.seekg(m_securityDirOffset, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(&m_certTableAddress), 4))
    {
        return;
    }
    if (!file.read(reinterpret_cast<char*>(&m_certTableSize), 4))
    {
        return;
    }

    if (m_certTableAddress == 0 || m_certTableSize < 8)
    {
        return;
    }

    file.seekg(m_certTableAddress, std::ios::beg);
    uint32_t dwLength = 0;
    uint16_t wRevision = 0;
    uint16_t wCertType = 0;
    if (!file.read(reinterpret_cast<char*>(&dwLength), 4))
    {
        return;
    }
    if (!file.read(reinterpret_cast<char*>(&wRevision), 2))
    {
        return;
    }
    if (!file.read(reinterpret_cast<char*>(&wCertType), 2))
    {
        return;
    }

    if (wCertType == 0x0002 && dwLength >= 8)
    {
        uint32_t pkcs7Len = dwLength - 8;
        std::vector<uint8_t> buf(pkcs7Len);
        if (file.read(reinterpret_cast<char*>(buf.data()), pkcs7Len))
        {
            BIOPtr bio(BIO_new_mem_buf(buf.data(), pkcs7Len));
            PKCS7* p7 = d2i_PKCS7_bio(bio.get(), nullptr);
            if (p7)
            {
                if (PKCS7_type_is_signed(p7) && p7->d.sign)
                {
                    STACK_OF(PKCS7_SIGNER_INFO)* siSk = p7->d.sign->signer_info;
                    if (siSk && sk_PKCS7_SIGNER_INFO_num(siSk) > 0)
                    {
                        PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(siSk, 0);
                        if (si && si->digest_alg && si->digest_alg->algorithm)
                        {
                            int nid = OBJ_obj2nid(si->digest_alg->algorithm);
                            m_signingAlgorithm = OpenSslHelper::getDigestAlgorithmName(nid);
                        }
                        if (si && si->unauth_attr)
                        {
                            for (int i = 0; i < sk_X509_ATTRIBUTE_num(si->unauth_attr); ++i)
                            {
                                X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(si->unauth_attr, i);
                                ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
                                if (obj)
                                {
                                    int attrNid = OBJ_obj2nid(obj);
                                    if (attrNid == NID_pkcs9_countersignature)
                                    {
                                        m_timestamp = "Present";
                                    }
                                }
                            }
                        }
                    }

                    if (p7->d.sign->cert)
                    {
                        STACK_OF(X509)* sk = p7->d.sign->cert;
                        for (int i = 0; i < sk_X509_num(sk); ++i)
                        {
                            X509* x = sk_X509_value(sk, i);
                            m_certs.push_back(X509Ptr(X509_dup(x)));
                        }
                        if (p7->d.sign->crl)
                        {
                            STACK_OF(X509_CRL)* crlSk = p7->d.sign->crl;
                            for (int i = 0; i < sk_X509_CRL_num(crlSk); ++i)
                            {
                                X509_CRL* c = sk_X509_CRL_value(crlSk, i);
                                m_crls.push_back(X509CRLPtr(X509_CRL_dup(c)));
                            }
                        }
                    }
                }
                PKCS7_free(p7);
            }
        }
    }
}

PKCS7Ptr OpenSslPeFileStore::getPkcs7()
{
    if (m_certTableAddress == 0 || m_certTableSize < 8)
    {
        return nullptr;
    }
    std::ifstream file(m_loadedLocation, std::ios::binary);
    if (!file.is_open())
    {
        return nullptr;
    }

    file.seekg(m_certTableAddress, std::ios::beg);
    uint32_t dwLength = 0;
    uint16_t wRevision = 0;
    uint16_t wCertType = 0;
    if (!file.read(reinterpret_cast<char*>(&dwLength), 4))
    {
        return nullptr;
    }
    if (!file.read(reinterpret_cast<char*>(&wRevision), 2))
    {
        return nullptr;
    }
    if (!file.read(reinterpret_cast<char*>(&wCertType), 2))
    {
        return nullptr;
    }

    if (wCertType == 0x0002 && dwLength >= 8)
    {
        uint32_t pkcs7Len = dwLength - 8;
        std::vector<uint8_t> buf(pkcs7Len);
        if (file.read(reinterpret_cast<char*>(buf.data()), pkcs7Len))
        {
            BIOPtr bio(BIO_new_mem_buf(buf.data(), pkcs7Len));
            return PKCS7Ptr(d2i_PKCS7_bio(bio.get(), nullptr));
        }
    }
    return nullptr;
}

bool OpenSslPeFileStore::setPkcs7(PKCS7* p7)
{
    if (!p7 || m_securityDirOffset == 0)
    {
        return false;
    }
    BIOPtr bio(BIO_new(BIO_s_mem()));
    if (i2d_PKCS7_bio(bio.get(), p7) != 1)
    {
        return false;
    }

    char* derData = nullptr;
    long derLen = BIO_get_mem_data(bio.get(), &derData);
    if (derLen <= 0 || !derData)
    {
        return false;
    }

    uint32_t paddedLen = (derLen + 7) & ~7;
    uint32_t dwLength = 8 + derLen;
    uint16_t wRevision = 0x0200;
    uint16_t wCertType = 0x0002;

    std::fstream file(m_loadedLocation, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    file.seekp(0, std::ios::end);
    uint32_t fileSize = file.tellp();

    uint32_t writeAddr = m_certTableAddress;
    if (writeAddr == 0)
    {
        writeAddr = fileSize;
    }

    file.seekp(writeAddr, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&dwLength), 4);
    file.write(reinterpret_cast<const char*>(&wRevision), 2);
    file.write(reinterpret_cast<const char*>(&wCertType), 2);
    file.write(derData, derLen);
    if (paddedLen > derLen)
    {
        std::vector<char> pad(paddedLen - derLen, 0);
        file.write(pad.data(), pad.size());
    }

    uint32_t newCertTableSize = 8 + paddedLen;
    file.seekp(m_securityDirOffset, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&writeAddr), 4);
    file.write(reinterpret_cast<const char*>(&newCertTableSize), 4);

    m_certTableAddress = writeAddr;
    m_certTableSize = newCertTableSize;
    return true;
}

void OpenSslPeFileStore::save(const std::string& location, const StoreOptions& options)
{
    if (location != m_loadedLocation && !m_loadedLocation.empty())
    {
        std::ifstream src(m_loadedLocation, std::ios::binary);
        std::ofstream dst(location, std::ios::binary);
        dst << src.rdbuf();
        m_loadedLocation = location;
    }

    PKCS7* p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);

    for (const auto& c : m_certs)
    {
        PKCS7_add_certificate(p7, c.get());
    }
    for (const auto& c : m_crls)
    {
        PKCS7_add_crl(p7, c.get());
    }

    bool res = setPkcs7(p7);
    PKCS7_free(p7);
    if (!res)
    {
        throw OpenSslException("Failed to save the store", false);
    }
}

std::vector<CertificatePtr> OpenSslPeFileStore::getCertificates()
{
    std::vector<CertificatePtr> list;
    for (const auto& c : m_certs)
    {
        list.push_back(std::make_shared<OpenSslCert>(c.get()));
    }
    return list;
}

std::vector<CrlPtr> OpenSslPeFileStore::getCrls()
{
    std::vector<CrlPtr> list;
    for (const auto& c : m_crls)
    {
        list.push_back(std::make_shared<OpenSslCrl>(c.get()));
    }
    return list;
}

std::vector<CtlPtr> OpenSslPeFileStore::getCtls() { return m_ctls; }

void OpenSslPeFileStore::addCertificate(CertificatePtr cert)
{
    if (!cert)
    {
        throw OpenSslException("Invalid certificate pointer", false);
    }
    auto der = cert->getEncoded();
    const unsigned char* p = der.data();
    X509* x = d2i_X509(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse certificate", false);
    }
    m_certs.push_back(X509Ptr(x));
}

void OpenSslPeFileStore::addCrl(CrlPtr crl)
{
    if (!crl)
    {
        throw OpenSslException("Invalid CRL pointer", false);
    }
    auto der = crl->getEncoded();
    const unsigned char* p = der.data();
    X509_CRL* x = d2i_X509_CRL(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse CRL", false);
    }
    m_crls.push_back(X509CRLPtr(x));
}

void OpenSslPeFileStore::addCtl(CtlPtr ctl)
{
    if (!ctl)
    {
        throw OpenSslException("Invalid CTL pointer", false);
    }
    m_ctls.push_back(ctl);
}

void OpenSslPeFileStore::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
{
    auto it = std::remove_if(m_certs.begin(), m_certs.end(),
        [&](const X509Ptr& c)
        {
            if (!commonName.empty() && OpenSslHelper::getCertCommonName(c.get()) != commonName)
            {
                return false;
            }
            if (!sha1Hash.empty() && OpenSslHelper::getCertSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_certs.erase(it, m_certs.end());
}

void OpenSslPeFileStore::deleteCrl(const std::string& sha1Hash)
{
    auto it = std::remove_if(m_crls.begin(), m_crls.end(),
        [&](const X509CRLPtr& c)
        {
            if (!sha1Hash.empty() && OpenSslHelper::getCrlSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_crls.erase(it, m_crls.end());
}

void OpenSslPeFileStore::deleteCtl(const std::string& sha1Hash)
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

void OpenSslPeFileStore::addPrivateKey(const std::string& pfxFilePath, const std::string& password)
{
    throw OpenSslException(
        "addPrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

void OpenSslPeFileStore::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "deletePrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

// AppxFileStore
void OpenSslAppxFileStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;
    m_signingAlgorithm = "sha256";
    m_timestamp = "None";

    if (!std::filesystem::exists(location))
    {
        throw OpenSslException("Failed to open the store", false);
    }

    try
    {
        ZipArchive archive(location);
        if (!archive.hasEntry("[Content_Types].xml"))
        {
            throw OpenSslException(
                "Invalid APPX/MSIX package, [Content_Types].xml is missing", false);
        }

        auto sigBuf = archive.getUncompressedContent("AppxSignature.p7x");
        if (sigBuf.size() > 8 && sigBuf[0] == 'P' && sigBuf[1] == 'K' && sigBuf[2] == 'C' &&
            sigBuf[3] == 'X')
        {
            BIOPtr bio(BIO_new_mem_buf(sigBuf.data() + 4, sigBuf.size() - 4));
            PKCS7* p7 = d2i_PKCS7_bio(bio.get(), nullptr);
            if (p7)
            {
                if (PKCS7_type_is_signed(p7) && p7->d.sign)
                {
                    STACK_OF(PKCS7_SIGNER_INFO)* siSk = p7->d.sign->signer_info;
                    if (siSk && sk_PKCS7_SIGNER_INFO_num(siSk) > 0)
                    {
                        PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(siSk, 0);
                        if (si && si->digest_alg && si->digest_alg->algorithm)
                        {
                            int nid = OBJ_obj2nid(si->digest_alg->algorithm);
                            m_signingAlgorithm = OpenSslHelper::getDigestAlgorithmName(nid);
                        }
                        if (si && si->unauth_attr)
                        {
                            for (int i = 0; i < sk_X509_ATTRIBUTE_num(si->unauth_attr); ++i)
                            {
                                X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(si->unauth_attr, i);
                                ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
                                if (obj)
                                {
                                    int attrNid = OBJ_obj2nid(obj);
                                    if (attrNid == NID_pkcs9_countersignature)
                                    {
                                        m_timestamp = "Present";
                                    }
                                }
                            }
                        }
                    }

                    if (p7->d.sign->cert)
                    {
                        STACK_OF(X509)* sk = p7->d.sign->cert;
                        for (int i = 0; i < sk_X509_num(sk); ++i)
                        {
                            X509* x = sk_X509_value(sk, i);
                            m_certs.push_back(X509Ptr(X509_dup(x)));
                        }
                        if (p7->d.sign->crl)
                        {
                            STACK_OF(X509_CRL)* crlSk = p7->d.sign->crl;
                            for (int i = 0; i < sk_X509_CRL_num(crlSk); ++i)
                            {
                                X509_CRL* c = sk_X509_CRL_value(crlSk, i);
                                m_crls.push_back(X509CRLPtr(X509_CRL_dup(c)));
                            }
                        }
                    }
                }
                PKCS7_free(p7);
            }
        }
    }
    catch (const std::exception& e)
    {
        throw OpenSslException(std::string("Failed to load store: ") + e.what(), false);
    }
}

void OpenSslAppxFileStore::save(const std::string& location, const StoreOptions& options)
{
    if (location != m_loadedLocation && !m_loadedLocation.empty())
    {
        std::filesystem::copy_file(
            m_loadedLocation, location, std::filesystem::copy_options::overwrite_existing);
        m_loadedLocation = location;
    }

    PKCS7* p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);

    for (const auto& c : m_certs)
    {
        PKCS7_add_certificate(p7, c.get());
    }
    for (const auto& c : m_crls)
    {
        PKCS7_add_crl(p7, c.get());
    }

    bool res = setPkcs7(p7);
    PKCS7_free(p7);
    if (!res)
    {
        throw OpenSslException("Failed to save the store", false);
    }
}

std::vector<CertificatePtr> OpenSslAppxFileStore::getCertificates()
{
    std::vector<CertificatePtr> list;
    for (const auto& c : m_certs)
    {
        list.push_back(std::make_shared<OpenSslCert>(c.get()));
    }
    return list;
}

std::vector<CrlPtr> OpenSslAppxFileStore::getCrls()
{
    std::vector<CrlPtr> list;
    for (const auto& c : m_crls)
    {
        list.push_back(std::make_shared<OpenSslCrl>(c.get()));
    }
    return list;
}

std::vector<CtlPtr> OpenSslAppxFileStore::getCtls() { return m_ctls; }

void OpenSslAppxFileStore::addCertificate(CertificatePtr cert)
{
    if (!cert)
    {
        throw OpenSslException("Invalid certificate pointer", false);
    }
    auto der = cert->getEncoded();
    const unsigned char* p = der.data();
    X509* x = d2i_X509(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse certificate", false);
    }
    m_certs.push_back(X509Ptr(x));
}

void OpenSslAppxFileStore::addCrl(CrlPtr crl)
{
    if (!crl)
    {
        throw OpenSslException("Invalid CRL pointer", false);
    }
    auto der = crl->getEncoded();
    const unsigned char* p = der.data();
    X509_CRL* x = d2i_X509_CRL(nullptr, &p, der.size());
    if (!x)
    {
        throw OpenSslException("Failed to parse CRL", false);
    }
    m_crls.push_back(X509CRLPtr(x));
}

void OpenSslAppxFileStore::addCtl(CtlPtr ctl)
{
    if (!ctl)
    {
        throw OpenSslException("Invalid CTL pointer", false);
    }
    m_ctls.push_back(ctl);
}

void OpenSslAppxFileStore::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
{
    auto it = std::remove_if(m_certs.begin(), m_certs.end(),
        [&](const X509Ptr& c)
        {
            if (!commonName.empty() && OpenSslHelper::getCertCommonName(c.get()) != commonName)
            {
                return false;
            }
            if (!sha1Hash.empty() && OpenSslHelper::getCertSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_certs.erase(it, m_certs.end());
}

void OpenSslAppxFileStore::deleteCrl(const std::string& sha1Hash)
{
    auto it = std::remove_if(m_crls.begin(), m_crls.end(),
        [&](const X509CRLPtr& c)
        {
            if (!sha1Hash.empty() && OpenSslHelper::getCrlSha1(c.get()) != sha1Hash)
            {
                return false;
            }
            return true;
        });
    m_crls.erase(it, m_crls.end());
}

void OpenSslAppxFileStore::deleteCtl(const std::string& sha1Hash)
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

void OpenSslAppxFileStore::addPrivateKey(
    const std::string& pfxFilePath, const std::string& password)
{
    throw OpenSslException(
        "addPrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

void OpenSslAppxFileStore::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "deletePrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

PKCS7Ptr OpenSslAppxFileStore::getPkcs7()
{
    try
    {
        ZipArchive archive(m_loadedLocation);
        auto sigBytes = archive.getUncompressedContent("AppxSignature.p7x");
        if (sigBytes.size() > 8 && sigBytes[0] == 'P' && sigBytes[1] == 'K' && sigBytes[2] == 'C' &&
            sigBytes[3] == 'X')
        {
            BIOPtr bio(BIO_new_mem_buf(sigBytes.data() + 4, sigBytes.size() - 4));
            return PKCS7Ptr(d2i_PKCS7_bio(bio.get(), nullptr));
        }
    }
    catch (const std::exception&)
    {
        return nullptr;
    }
    return nullptr;
}

bool OpenSslAppxFileStore::setPkcs7(PKCS7* p7)
{
    if (!p7)
    {
        return false;
    }
    BIOPtr bio(BIO_new(BIO_s_mem()));
    if (i2d_PKCS7_bio(bio.get(), p7) != 1)
    {
        return false;
    }

    char* derData = nullptr;
    long derLen = BIO_get_mem_data(bio.get(), &derData);
    if (derLen <= 0 || !derData)
    {
        return false;
    }

    std::vector<uint8_t> sigBytes(4 + derLen);
    sigBytes[0] = 'P';
    sigBytes[1] = 'K';
    sigBytes[2] = 'C';
    sigBytes[3] = 'X';
    std::memcpy(sigBytes.data() + 4, derData, derLen);

    try
    {
        ZipArchive archive(m_loadedLocation);
        archive.setEntryContent("AppxSignature.p7x", sigBytes, false);
        archive.save(m_loadedLocation);
    }
    catch (const std::exception&)
    {
        return false;
    }
    return true;
}

// WinSystemStore stub
void OpenSslWinSystemStore::load(const std::string& location, const StoreOptions& options)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::save(const std::string& location, const StoreOptions& options)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
std::vector<CertificatePtr> OpenSslWinSystemStore::getCertificates()
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
std::vector<CrlPtr> OpenSslWinSystemStore::getCrls()
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
std::vector<CtlPtr> OpenSslWinSystemStore::getCtls()
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::addCertificate(CertificatePtr cert)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::addCrl(CrlPtr crl)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::addCtl(CtlPtr ctl)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::deleteCrl(const std::string& sha1Hash)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::deleteCtl(const std::string& sha1Hash)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::addPrivateKey(
    const std::string& pfxFilePath, const std::string& password)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}
void OpenSslWinSystemStore::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "Windows system certificate stores are unsupported on this platform (OpenSSL backend).",
        false);
}

// OpenSslPfxCertStore
void OpenSslPfxCertStore::load(const std::string& location, const StoreOptions& options)
{
    m_certs.clear();
    m_crls.clear();
    m_ctls.clear();
    m_loadedLocation = location;

    BIOPtr bio(BIO_new_file(location.c_str(), "rb"));
    if (!bio)
    {
        throw OpenSslException("Failed to open the store", false);
    }

    PKCS12* p12 = d2i_PKCS12_bio(bio.get(), nullptr);
    if (p12)
    {
        X509* c = nullptr;
        EVP_PKEY* k = nullptr;
        STACK_OF(X509)* ca = nullptr;
        if (PKCS12_parse(p12, options.password.c_str(), &k, &c, &ca) == 1)
        {
            if (c)
            {
                m_certs.push_back(std::make_shared<OpenSslPfxCert>(c, k));
                X509_free(c);
            }
            if (k)
            {
                EVP_PKEY_free(k);
            }
            if (ca)
            {
                sk_X509_pop_free(ca, X509_free);
            }
        }
        PKCS12_free(p12);
    }
    else
    {
        throw OpenSslException("Failed to parse PFX/PKCS12 store.", false);
    }
}

void OpenSslPfxCertStore::save(const std::string& location, const StoreOptions& options)
{
    throw OpenSslException("Saving to PFX/PKCS12 store is unsupported.", false);
}

std::vector<CertificatePtr> OpenSslPfxCertStore::getCertificates() { return m_certs; }

std::vector<CrlPtr> OpenSslPfxCertStore::getCrls() { return m_crls; }

std::vector<CtlPtr> OpenSslPfxCertStore::getCtls() { return m_ctls; }

void OpenSslPfxCertStore::addCertificate(CertificatePtr cert)
{
    if (!cert)
    {
        throw OpenSslException("Invalid certificate pointer", false);
    }
    m_certs.push_back(cert);
}

void OpenSslPfxCertStore::addCrl(CrlPtr crl)
{
    if (!crl)
    {
        throw OpenSslException("Invalid CRL pointer", false);
    }
    m_crls.push_back(crl);
}

void OpenSslPfxCertStore::addCtl(CtlPtr ctl)
{
    if (!ctl)
    {
        throw OpenSslException("Invalid CTL pointer", false);
    }
    m_ctls.push_back(ctl);
}

void OpenSslPfxCertStore::deleteCertificate(
    const std::string& commonName, const std::string& sha1Hash)
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

void OpenSslPfxCertStore::deleteCrl(const std::string& sha1Hash)
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

void OpenSslPfxCertStore::deleteCtl(const std::string& sha1Hash)
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

void OpenSslPfxCertStore::addPrivateKey(const std::string& pfxFilePath, const std::string& password)
{
    throw OpenSslException(
        "addPrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

void OpenSslPfxCertStore::deletePrivateKey(
    const std::string& commonName, const std::string& sha1Hash)
{
    throw OpenSslException(
        "deletePrivateKey is unsupported on this platform (OpenSSL backend).", false);
}

} // namespace crypto
} // namespace ccky
