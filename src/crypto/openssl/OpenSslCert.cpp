#include "crypto/openssl/OpenSslCert.h"

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
    std::vector<uint8_t> res(buf, buf + len);
    OPENSSL_free(buf);
    return res;
}

OpenSslCtl::OpenSslCtl(const std::vector<uint8_t>& derBytes) : m_der(derBytes) {}

std::string OpenSslCtl::getSha1() const { return OpenSslHelper::getBufferSha1(m_der); }

std::vector<uint8_t> OpenSslCtl::getEncoded() const { return m_der; }

} // namespace crypto
} // namespace ccky
