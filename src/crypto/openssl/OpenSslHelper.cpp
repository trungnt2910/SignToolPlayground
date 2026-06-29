#include "crypto/openssl/OpenSslHelper.h"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "crypto/TimeFormatter.h"
#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

std::string OpenSslHelper::getOpenSslError()
{
    unsigned long errCode = ERR_get_error();
    if (errCode == 0)
    {
        return "No OpenSSL error";
    }
    char buf[256];
    ERR_error_string_n(errCode, buf, sizeof(buf));
    return std::string(buf);
}

std::string OpenSslHelper::getCertCommonName(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    X509_NAME* subj = X509_get_subject_name(cert);
    if (!subj)
    {
        return "";
    }
    int loc = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (loc < 0)
    {
        return "";
    }
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subj, loc);
    if (!entry)
    {
        return "";
    }
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
    {
        return "";
    }
    unsigned char* raw_utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&raw_utf8, data);
    if (len < 0 || !raw_utf8)
    {
        return "";
    }
    OpenSslBufferPtr utf8(raw_utf8);
    std::string res(reinterpret_cast<char*>(utf8.get()), len);
    return res;
}

std::string OpenSslHelper::getCertIssuerName(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    X509_NAME* issuer = X509_get_issuer_name(cert);
    if (!issuer)
    {
        return "";
    }
    int loc = X509_NAME_get_index_by_NID(issuer, NID_commonName, -1);
    if (loc < 0)
    {
        return "";
    }
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(issuer, loc);
    if (!entry)
    {
        return "";
    }
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
    {
        return "";
    }
    unsigned char* raw_utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&raw_utf8, data);
    if (len < 0 || !raw_utf8)
    {
        return "";
    }
    OpenSslBufferPtr utf8(raw_utf8);
    std::string res(reinterpret_cast<char*>(utf8.get()), len);
    return res;
}

std::string OpenSslHelper::getNameDisplay(X509_NAME* name)
{
    if (!name)
    {
        return "";
    }
    int count = X509_NAME_entry_count(name);
    if (count <= 0)
    {
        return "";
    }

    std::stringstream ss;
    int currentSet = -1;
    int avaIdx = 0;

    for (int i = 0; i < count; ++i)
    {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        if (!entry)
        {
            continue;
        }

        int set = X509_NAME_ENTRY_set(entry);
        if (set != currentSet)
        {
            currentSet = set;
            avaIdx = 0;
        }
        else
        {
            avaIdx++;
        }

        ss << "[" << set << "," << avaIdx << "] ";

        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        if (obj)
        {
            char oidBuf[128] = {0};
            OBJ_obj2txt(oidBuf, sizeof(oidBuf), obj, 1);
            ss << oidBuf;

            int nid = OBJ_obj2nid(obj);
            const char* sn = OBJ_nid2sn(nid);
            if (sn && strlen(sn) > 0)
            {
                std::string upperSn = sn;
                std::transform(upperSn.begin(), upperSn.end(), upperSn.begin(), ::toupper);
                ss << " (" << upperSn << ")";
            }
        }

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (data)
        {
            unsigned char* raw_utf8 = nullptr;
            int len = ASN1_STRING_to_UTF8(&raw_utf8, data);
            if (len > 0 && raw_utf8)
            {
                OpenSslBufferPtr utf8(raw_utf8);
                ss << " " << std::string(reinterpret_cast<char*>(utf8.get()), len);
            }
        }

        if (i + 1 < count)
        {
            ss << "\n  ";
        }
    }

    return ss.str();
}

std::string OpenSslHelper::getNameDN(X509_NAME* name)
{
    if (!name)
    {
        return "";
    }
    BIOPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
    {
        return "";
    }
    X509_NAME_print_ex(
        bio.get(), name, 0, (XN_FLAG_ONELINE & ~XN_FLAG_SPC_EQ) & ~ASN1_STRFLGS_ESC_MSB);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    std::string res(data, len);
    return res;
}

std::string OpenSslHelper::getCertSha1(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_digest(cert, EVP_sha1(), md, &len) != 1)
    {
        return "";
    }
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
    }
    return ss.str();
}

std::string OpenSslHelper::getCrlSha1(X509_CRL* crl)
{
    if (!crl)
    {
        return "";
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_CRL_digest(crl, EVP_sha1(), md, &len) != 1)
    {
        return "";
    }
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
    }
    return ss.str();
}

std::string OpenSslHelper::getBufferSha1(const std::vector<uint8_t>& data)
{
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) != 1)
    {
        return "";
    }
    if (!data.empty() && EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
    {
        return "";
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), md, &len) != 1)
    {
        return "";
    }
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
    }
    return ss.str();
}

std::string OpenSslHelper::getBufferSha256(const std::vector<uint8_t>& data)
{
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
    {
        return "";
    }
    if (!data.empty() && EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
    {
        return "";
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), md, &len) != 1)
    {
        return "";
    }
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(md[i]);
    }
    return ss.str();
}

std::string OpenSslHelper::getCertSerialNumber(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert);
    if (!serial)
    {
        return "";
    }
    const uint8_t* data = ASN1_STRING_get0_data(serial);
    int len = ASN1_STRING_length(serial);
    std::stringstream ss;
    for (int i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(data[i]);
        if (i + 1 < len)
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string OpenSslHelper::getCertThumbprint(X509* cert, const EVP_MD* md, bool spaceEvery8)
{
    if (!cert || !md)
    {
        return "";
    }
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_digest(cert, md, buf, &len) != 1)
    {
        return "";
    }
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(buf[i]);
        if (spaceEvery8 && (i % 4 == 3) && (i + 1 < len))
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string OpenSslHelper::getCertKeyMd5Thumbprint(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey)
    {
        return "";
    }
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0 || !der)
    {
        return "";
    }
    OpenSslBufferPtr derPtr(der);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (ctx && EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx.get(), derPtr.get(), len) == 1 &&
        EVP_DigestFinal_ex(ctx.get(), md, &mdLen) == 1)
    {
        std::stringstream ss;
        for (unsigned int i = 0; i < mdLen; ++i)
        {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(md[i]);
            if ((i % 4 == 3) && (i + 1 < mdLen))
            {
                ss << " ";
            }
        }
        return ss.str();
    }
    return "";
}

std::string OpenSslHelper::getCertKeySha256Thumbprint(X509* cert)
{
    if (!cert)
    {
        return "";
    }
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey)
    {
        return "";
    }
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0 || !der)
    {
        return "";
    }
    OpenSslBufferPtr derPtr(der);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx.get(), derPtr.get(), len) == 1 &&
        EVP_DigestFinal_ex(ctx.get(), md, &mdLen) == 1)
    {
        std::stringstream ss;
        for (unsigned int i = 0; i < mdLen; ++i)
        {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(md[i]);
        }
        return ss.str();
    }
    return "";
}

std::string OpenSslHelper::getCertTime(const ASN1_TIME* time)
{
    if (!time)
    {
        return "";
    }
    struct tm t;
    memset(&t, 0, sizeof(t));
    if (ASN1_TIME_to_tm(time, &t) != 1)
    {
        return "";
    }
    time_t rawtime = timegm(&t);
    if (rawtime == -1)
    {
        return "";
    }
    auto tp = std::chrono::system_clock::from_time_t(rawtime);
    return TimeFormatter::formatTime(tp);
}

const EVP_MD* OpenSslHelper::getDigestAlgorithm(const std::string& alg)
{
    std::string lower = alg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "sha1")
    {
        return EVP_sha1();
    }
    if (lower == "sha256")
    {
        return EVP_sha256();
    }
    if (lower == "sha384")
    {
        return EVP_sha384();
    }
    if (lower == "sha512")
    {
        return EVP_sha512();
    }
    return EVP_sha1();
}

std::string OpenSslHelper::getDigestAlgorithmName(int nid)
{
    if (nid == NID_sha1)
    {
        return "sha1";
    }
    if (nid == NID_sha256)
    {
        return "sha256";
    }
    if (nid == NID_sha384)
    {
        return "sha384";
    }
    if (nid == NID_sha512)
    {
        return "sha512";
    }
    const char* sn = OBJ_nid2sn(nid);
    return sn ? sn : "sha256";
}

} // namespace crypto
} // namespace ccky
