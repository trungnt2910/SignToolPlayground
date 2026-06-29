#ifndef CCKY_OPENSSL_CERT_H
#define CCKY_OPENSSL_CERT_H

#include "crypto/Certificate.h"
#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

class OpenSslCert : public Certificate
{
  public:
    explicit OpenSslCert(X509* cert, EVP_PKEY* pkey = nullptr);
    ~OpenSslCert() override;

    std::string getCommonName() const override;
    std::string getIssuerName() const override;
    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    std::string getSubjectDisplay() const override;
    std::string getIssuerDisplay() const override;
    std::string getSubjectDN() const override;
    std::string getIssuerDN() const override;
    std::string getSerialNumber() const override;
    std::string getSha1Thumbprint() const override;
    std::string getMd5Thumbprint() const override;
    std::string getKeyMd5Thumbprint() const override;
    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
    std::string getNotBefore() const override;
    std::string getNotAfter() const override;
    bool isCA() const override;
    int getPathLenConstraint() const override;
    int getKeyLength() const override;
    std::vector<std::string> getEnhancedKeyUsage() const override;
    std::string getSignatureAlgorithm() const override;
    uint32_t getNetscapeCertType() const override;
    std::string getKeySha256Thumbprint() const override;
    bool isPrivateKeyExportable() const override;
    std::string getPolicyLink() const override;

    X509* getInternal() const { return m_cert.get(); }
    EVP_PKEY* getPrivateKey() const { return m_pkey.get(); }

  private:
    X509Ptr m_cert;
    EVPPKeyPtr m_pkey;
};

class OpenSslPfxCert : public OpenSslCert
{
  public:
    explicit OpenSslPfxCert(X509* cert, EVP_PKEY* pkey = nullptr);
    ~OpenSslPfxCert() override = default;

    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
};

class OpenSslCrl : public Crl
{
  public:
    explicit OpenSslCrl(X509_CRL* crl);
    ~OpenSslCrl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    X509_CRL* getInternal() const { return m_crl.get(); }

  private:
    X509CRLPtr m_crl;
};

class OpenSslCtl : public Ctl
{
  public:
    explicit OpenSslCtl(const std::vector<uint8_t>& derBytes);
    ~OpenSslCtl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

  private:
    std::vector<uint8_t> m_der;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_CERT_H
