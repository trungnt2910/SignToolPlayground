#include "crypto/openssl/OpenSslCert.h"

#include "crypto/openssl/OpenSslHelper.h"
#include "crypto/openssl/SpcStructures.h"

namespace ccky
{
namespace crypto
{

OpenSslCert::OpenSslCert(X509* cert, EVP_PKEY* pkey)
{
    if (cert)
    {
        m_cert.reset(X509_dup(cert));
    }
    if (pkey)
    {
        EVP_PKEY_up_ref(pkey);
        m_pkey.reset(pkey);
    }
}

OpenSslCert::~OpenSslCert() = default;

std::string OpenSslCert::getCommonName() const
{
    return OpenSslHelper::getCertCommonName(m_cert.get());
}

std::string OpenSslCert::getIssuerName() const
{
    return OpenSslHelper::getCertIssuerName(m_cert.get());
}

std::string OpenSslCert::getSha1() const { return OpenSslHelper::getCertSha1(m_cert.get()); }

std::vector<uint8_t> OpenSslCert::getEncoded() const
{
    if (!m_cert)
    {
        return {};
    }
    unsigned char* buf = nullptr;
    int len = i2d_X509(m_cert.get(), &buf);
    if (len <= 0 || !buf)
    {
        return {};
    }
    std::vector<uint8_t> res(buf, buf + len);
    OPENSSL_free(buf);
    return res;
}

std::string OpenSslCert::getSubjectDisplay() const
{
    if (!m_cert)
    {
        return "";
    }
    return OpenSslHelper::getNameDisplay(X509_get_subject_name(m_cert.get()));
}
std::string OpenSslCert::getIssuerDisplay() const
{
    if (!m_cert)
    {
        return "";
    }
    return OpenSslHelper::getNameDisplay(X509_get_issuer_name(m_cert.get()));
}

std::string OpenSslCert::getSubjectDN() const
{
    if (!m_cert)
    {
        return "";
    }
    return OpenSslHelper::getNameDN(X509_get_subject_name(m_cert.get()));
}

std::string OpenSslCert::getIssuerDN() const
{
    if (!m_cert)
    {
        return "";
    }
    return OpenSslHelper::getNameDN(X509_get_issuer_name(m_cert.get()));
}

std::string OpenSslCert::getSerialNumber() const
{
    return OpenSslHelper::getCertSerialNumber(m_cert.get());
}
std::string OpenSslCert::getSha1Thumbprint() const
{
    return OpenSslHelper::getCertThumbprint(m_cert.get(), EVP_sha1(), true);
}
std::string OpenSslCert::getMd5Thumbprint() const
{
    return OpenSslHelper::getCertThumbprint(m_cert.get(), EVP_md5(), true);
}
std::string OpenSslCert::getKeyMd5Thumbprint() const
{
    return OpenSslHelper::getCertKeyMd5Thumbprint(m_cert.get());
}
std::string OpenSslCert::getProviderType() const { return ""; }
std::string OpenSslCert::getProviderName() const { return ""; }
std::string OpenSslCert::getContainerName() const { return ""; }
std::string OpenSslCert::getNotBefore() const
{
    return OpenSslHelper::getCertTime(X509_get0_notBefore(m_cert.get()));
}
std::string OpenSslCert::getNotAfter() const
{
    return OpenSslHelper::getCertTime(X509_get0_notAfter(m_cert.get()));
}

bool OpenSslCert::isCA() const
{
    if (!m_cert)
    {
        return false;
    }
    return X509_check_ca(m_cert.get()) == 1;
}

int OpenSslCert::getPathLenConstraint() const
{
    if (!m_cert)
    {
        return -1;
    }
    return X509_get_pathlen(m_cert.get());
}

int OpenSslCert::getKeyLength() const
{
    if (!m_cert)
    {
        return 0;
    }
    EVPPKeyPtr pubkey(X509_get_pubkey(m_cert.get()));
    if (!pubkey)
    {
        return 0;
    }
    return EVP_PKEY_bits(pubkey.get());
}

std::vector<std::string> OpenSslCert::getEnhancedKeyUsage() const
{
    std::vector<std::string> res;
    if (!m_cert)
    {
        return res;
    }
    EKUPtr eku(
        (EXTENDED_KEY_USAGE*)X509_get_ext_d2i(m_cert.get(), NID_ext_key_usage, nullptr, nullptr));
    if (!eku)
    {
        return res;
    }
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku.get()); ++i)
    {
        char buf[80];
        OBJ_obj2txt(buf, sizeof(buf), sk_ASN1_OBJECT_value(eku.get(), i), 1);
        res.push_back(buf);
    }
    return res;
}

std::string OpenSslCert::getSignatureAlgorithm() const
{
    if (!m_cert)
    {
        return "";
    }
    int nid = X509_get_signature_nid(m_cert.get());
    char buf[80];
    OBJ_obj2txt(buf, sizeof(buf), OBJ_nid2obj(nid), 1);
    return buf;
}

uint32_t OpenSslCert::getNetscapeCertType() const
{
    if (!m_cert)
    {
        return 0;
    }
    ASN1BitStringPtr nsType(
        (ASN1_BIT_STRING*)X509_get_ext_d2i(m_cert.get(), NID_netscape_cert_type, nullptr, nullptr));
    if (!nsType)
    {
        return 0;
    }
    uint32_t val = 0;
    if (nsType->length > 0)
    {
        val = nsType->data[0];
    }
    return val;
}

std::string OpenSslCert::getKeySha256Thumbprint() const
{
    if (!m_cert)
    {
        return "";
    }
    return OpenSslHelper::getCertKeySha256Thumbprint(m_cert.get());
}

bool OpenSslCert::isPrivateKeyExportable() const { return true; }

std::string OpenSslCert::getPolicyLink() const
{
    if (!m_cert)
    {
        return "";
    }
    ASN1ObjectPtr obj(OBJ_txt2obj(OID_SPC_SP_AGENCY_INFO, 1));
    if (!obj)
    {
        return "";
    }
    int pos = X509_get_ext_by_OBJ(m_cert.get(), obj.get(), -1);
    if (pos < 0)
    {
        return "";
    }
    X509_EXTENSION* ext = X509_get_ext(m_cert.get(), pos);
    if (!ext)
    {
        return "";
    }
    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data)
    {
        return "";
    }
    const unsigned char* p = ASN1_STRING_get0_data(data);
    SpcSpAgencyInfoPtr info(d2i_SPC_SP_AGENCY_INFO(nullptr, &p, ASN1_STRING_length(data)));
    if (!info)
    {
        return "";
    }
    if (info->policyInformation)
    {
        return (char*)ASN1_STRING_get0_data(info->policyInformation);
    }
    return "";
}

OpenSslPfxCert::OpenSslPfxCert(X509* cert, EVP_PKEY* pkey) : OpenSslCert(cert, pkey) {}

std::string OpenSslPfxCert::getProviderType() const { return "0"; }

std::string OpenSslPfxCert::getProviderName() const { return "PfxProvider"; }

std::string OpenSslPfxCert::getContainerName() const { return "PfxContainer"; }

OpenSslCrl::OpenSslCrl(X509_CRL* crl)
{
    if (crl)
    {
        m_crl.reset(X509_CRL_dup(crl));
    }
}

std::string OpenSslCrl::getSha1() const { return OpenSslHelper::getCrlSha1(m_crl.get()); }

std::vector<uint8_t> OpenSslCrl::getEncoded() const
{
    if (!m_crl)
    {
        return {};
    }
    unsigned char* buf = nullptr;
    int len = i2d_X509_CRL(m_crl.get(), &buf);
    if (len <= 0 || !buf)
    {
        return {};
    }
    OpenSslBufferPtr bufPtr(buf);
    return std::vector<uint8_t>(bufPtr.get(), bufPtr.get() + len);
}

OpenSslCtl::OpenSslCtl(const std::vector<uint8_t>& derBytes) : m_der(derBytes) {}

std::string OpenSslCtl::getSha1() const { return OpenSslHelper::getBufferSha1(m_der); }

std::vector<uint8_t> OpenSslCtl::getEncoded() const { return m_der; }

} // namespace crypto
} // namespace ccky
