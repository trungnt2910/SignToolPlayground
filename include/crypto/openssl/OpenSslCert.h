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
    explicit OpenSslCert(X509Ptr cert, EVPPKeyPtr pkey = nullptr);
    ~OpenSslCert() override;

    // Encoding, Hashes & Algorithms
    std::vector<uint8_t> getEncoded() const override;
    std::string getSerialNumber() const override;
    std::string getSha1() const override;
    std::string getSha1Thumbprint() const override;
    std::string getMd5Thumbprint() const override;
    std::string getSignatureAlgorithm() const override;

    // Subject Information
    std::string getCommonName() const override;
    std::string getSubjectDisplay() const override;
    std::string getSubjectDN() const override;

    // Issuer Information
    std::string getIssuerName() const override;
    std::string getIssuerDisplay() const override;
    std::string getIssuerDN() const override;

    // Validity Period
    std::string getNotBefore() const override;
    std::string getNotAfter() const override;

    // Key Information
    int getKeyLength() const override;
    std::string getKeyMd5Thumbprint() const override;
    std::string getKeySha256Thumbprint() const override;

    // Private Key Information
    bool hasPrivateKey() const override;
    PrivateKeyPtr getPrivateKey() const override;
    bool isPrivateKeyExportable() const override;

    // Provider Information
    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;

    // Extensions & Policy Attributes
    bool isCA() const override;
    int getPathLenConstraint() const override;
    std::vector<std::string> getEnhancedKeyUsage() const override;
    uint32_t getNetscapeCertType() const override;
    std::string getPolicyLink() const override;

    const X509Ptr& getInternal() const { return m_cert; }
    const EVPPKeyPtr& getInternalKey() const { return m_pkey; }

  private:
    X509Ptr m_cert;
    EVPPKeyPtr m_pkey;
};

class OpenSslPfxCert : public OpenSslCert
{
  public:
    explicit OpenSslPfxCert(X509Ptr cert, EVPPKeyPtr pkey = nullptr);
    ~OpenSslPfxCert() override = default;

    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
};

class OpenSslCrl : public Crl
{
  public:
    explicit OpenSslCrl(X509CRLPtr crl);
    ~OpenSslCrl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    const X509CRLPtr& getInternal() const { return m_crl; }

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
