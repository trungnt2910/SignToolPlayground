#ifndef CCKY_WIN_CERT_H
#define CCKY_WIN_CERT_H

#include "crypto/Certificate.h"

#include <windows.h>

#include <wincrypt.h>

#include "crypto/windows/WinWrapper.h"

namespace ccky
{
namespace crypto
{

class WinCert : public Certificate
{
  public:
    explicit WinCert(PCCERT_CONTEXT cert);
    ~WinCert() override = default;

    std::string getCommonName() const override;
    std::string getIssuerName() const override;
    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    std::string getSubjectDisplay() const override;
    std::string getIssuerDisplay() const override;
    std::string getSerialNumber() const override;
    std::string getSha1Thumbprint() const override;
    std::string getMd5Thumbprint() const override;
    std::string getKeyMd5Thumbprint() const override;
    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
    std::string getNotBefore() const override;
    std::string getNotAfter() const override;

    PCCERT_CONTEXT getInternal() const { return m_cert.get(); }

  private:
    std::string getNameDisplay(const CERT_NAME_BLOB* pNameBlob) const;
    CertContextPtr m_cert;
};

class WinPfxCert : public WinCert
{
  public:
    explicit WinPfxCert(PCCERT_CONTEXT cert);
    ~WinPfxCert() override = default;

    std::string getProviderType() const override;
    std::string getProviderName() const override;
    std::string getContainerName() const override;
};

class WinCrl : public Crl
{
  public:
    explicit WinCrl(PCCRL_CONTEXT crl);
    ~WinCrl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    PCCRL_CONTEXT getInternal() const { return m_crl.get(); }

  private:
    CrlContextPtr m_crl;
};

class WinCtl : public Ctl
{
  public:
    explicit WinCtl(PCCTL_CONTEXT ctl);
    ~WinCtl() override = default;

    std::string getSha1() const override;
    std::vector<uint8_t> getEncoded() const override;

    PCCTL_CONTEXT getInternal() const { return m_ctl.get(); }

  private:
    CtlContextPtr m_ctl;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN_CERT_H
