#ifndef CCKY_OPENSSL_STORE_H
#define CCKY_OPENSSL_STORE_H

#include "crypto/ICertStore.h"
#include "crypto/openssl/OpenSslCert.h"

namespace ccky
{
namespace crypto
{

class OpenSslCerFileStore : public ICertStore
{
  public:
    StoreType getStoreType() const override { return StoreType::CerFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

    std::string getSigningAlgorithm() override { return ""; }
    std::string getTimestamp() override { return "None"; }

    std::vector<CertificatePtr> getCertificates() override;
    std::vector<CrlPtr> getCrls() override;
    std::vector<CtlPtr> getCtls() override;

    void addCertificate(CertificatePtr cert) override;
    void addCrl(CrlPtr crl) override;
    void addCtl(CtlPtr ctl) override;

    void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) override;
    void deleteCrl(const std::string& sha1Hash) override;
    void deleteCtl(const std::string& sha1Hash) override;

    void addPrivateKey(const std::string& pfxFilePath, const std::string& password = "") override;
    void deletePrivateKey(const std::string& commonName, const std::string& sha1Hash) override;

    bool saveAsPkcs7(const std::string& location);

  private:
    std::vector<X509Ptr> m_certs;
    std::vector<X509CRLPtr> m_crls;
    std::vector<CtlPtr> m_ctls;
    std::string m_loadedLocation;
};

class OpenSslPeFileStore : public ICertStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PeFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

    std::string getSigningAlgorithm() override { return m_signingAlgorithm; }
    std::string getTimestamp() override { return m_timestamp.empty() ? "None" : m_timestamp; }

    std::vector<CertificatePtr> getCertificates() override;
    std::vector<CrlPtr> getCrls() override;
    std::vector<CtlPtr> getCtls() override;

    void addCertificate(CertificatePtr cert) override;
    void addCrl(CrlPtr crl) override;
    void addCtl(CtlPtr ctl) override;

    void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) override;
    void deleteCrl(const std::string& sha1Hash) override;
    void deleteCtl(const std::string& sha1Hash) override;

    void addPrivateKey(const std::string& pfxFilePath, const std::string& password = "") override;
    void deletePrivateKey(const std::string& commonName, const std::string& sha1Hash) override;

    PKCS7Ptr getPkcs7();
    bool setPkcs7(PKCS7* p7);

  private:
    std::vector<X509Ptr> m_certs;
    std::vector<X509CRLPtr> m_crls;
    std::vector<CtlPtr> m_ctls;
    std::string m_loadedLocation;

    uint32_t m_securityDirOffset = 0;
    uint32_t m_certTableAddress = 0;
    uint32_t m_certTableSize = 0;
    bool m_isPe32Plus = false;
    std::string m_signingAlgorithm;
    std::string m_timestamp;
};

class OpenSslWinSystemStore : public ICertStore
{
  public:
    StoreType getStoreType() const override { return StoreType::WinSystem; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

    std::string getSigningAlgorithm() override { return ""; }
    std::string getTimestamp() override { return "None"; }

    std::vector<CertificatePtr> getCertificates() override;
    std::vector<CrlPtr> getCrls() override;
    std::vector<CtlPtr> getCtls() override;

    void addCertificate(CertificatePtr cert) override;
    void addCrl(CrlPtr crl) override;
    void addCtl(CtlPtr ctl) override;

    void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) override;
    void deleteCrl(const std::string& sha1Hash) override;
    void deleteCtl(const std::string& sha1Hash) override;

    void addPrivateKey(const std::string& pfxFilePath, const std::string& password = "") override;
    void deletePrivateKey(const std::string& commonName, const std::string& sha1Hash) override;
};

class OpenSslPfxCertStore : public ICertStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PfxFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

    std::string getSigningAlgorithm() override { return ""; }
    std::string getTimestamp() override { return "None"; }

    std::vector<CertificatePtr> getCertificates() override;
    std::vector<CrlPtr> getCrls() override;
    std::vector<CtlPtr> getCtls() override;

    void addCertificate(CertificatePtr cert) override;
    void addCrl(CrlPtr crl) override;
    void addCtl(CtlPtr ctl) override;

    void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) override;
    void deleteCrl(const std::string& sha1Hash) override;
    void deleteCtl(const std::string& sha1Hash) override;

    void addPrivateKey(const std::string& pfxFilePath, const std::string& password = "") override;
    void deletePrivateKey(const std::string& commonName, const std::string& sha1Hash) override;

  private:
    std::vector<CertificatePtr> m_certs;
    std::vector<CrlPtr> m_crls;
    std::vector<CtlPtr> m_ctls;
    std::string m_loadedLocation;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_STORE_H
