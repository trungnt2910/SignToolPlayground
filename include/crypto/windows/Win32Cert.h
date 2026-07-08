#ifndef CCKY_WIN32_CERT_H
#define CCKY_WIN32_CERT_H

#include <windows.h>

#include <wincrypt.h>

#include "crypto/Certificate.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

class Win32Cert : public Certificate
{
  public:
    explicit Win32Cert(CertContextPtr cert);
    ~Win32Cert() override = default;

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

    PCCERT_CONTEXT getInternal() const { return m_cert.get(); }

  private:
    std::string getNameDisplay(const CERT_NAME_BLOB* pNameBlob) const;
    std::string getNameDN(const CERT_NAME_BLOB* pNameBlob) const;
    CertContextPtr m_cert;
};

class Win32PfxCert : public Win32Cert
{
  public:
    explicit Win32PfxCert(CertContextPtr cert);
    ~Win32PfxCert() override = default;

    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
};

class Win32Crl : public Crl
{
  public:
    explicit Win32Crl(CrlContextPtr crl);
    ~Win32Crl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    PCCRL_CONTEXT getInternal() const { return m_crl.get(); }

  private:
    CrlContextPtr m_crl;
};

class Win32Ctl : public Ctl
{
  public:
    explicit Win32Ctl(CtlContextPtr ctl);
    ~Win32Ctl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    PCCTL_CONTEXT getInternal() const { return m_ctl.get(); }

  private:
    CtlContextPtr m_ctl;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_CERT_H
