#ifndef CCKY_WIN32_STORE_H
#define CCKY_WIN32_STORE_H

#include <memory>
#include <string>
#include <vector>

#include <windows.h>

#include <wincrypt.h>

#include "crypto/CertificateStore.h"
#include "crypto/windows/KeySetDeleter.h"
#include "crypto/windows/Win32Cert.h"

namespace ccky
{
namespace crypto
{

class Win32CommonStore : public CertificateStore
{
  public:
    ~Win32CommonStore() override = default;

    StoreType getStoreType() const override = 0;
    void load(const std::string& location, const StoreOptions& options = {}) override = 0;
    void save(const std::string& location, const StoreOptions& options = {}) override = 0;

    std::string getSigningAlgorithm() override { return m_signingAlgorithm; }
    std::string getTimestamp() override { return m_timestamp.empty() ? "None" : m_timestamp; }

  protected:
    virtual CertificatePtr createCert(CertContextPtr pCert) const;

    std::string m_loadedLocation;
    std::string m_signingAlgorithm;
    std::string m_timestamp;
};

class Win32FileStore : public Win32CommonStore
{
  public:
    ~Win32FileStore() override = default;

    std::vector<CertificatePtr> getCertificates() override;
    std::vector<CrlPtr> getCrls() override;
    std::vector<CtlPtr> getCtls() override;

    void addCertificate(CertificatePtr cert) override;
    void addCrl(CrlPtr crl) override;
    void addCtl(CtlPtr ctl) override;

    void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) override;
    void deleteCrl(const std::string& sha1Hash) override;
    void deleteCtl(const std::string& sha1Hash) override;

  protected:
    void populateFromStore(HCERTSTORE hStore);
    void loadSipFile(const std::string& location, const StoreOptions& options);
    void saveSipFile(const std::string& location, const StoreOptions& options);

    std::vector<CertificatePtr> m_certs;
    std::vector<CrlPtr> m_crls;
    std::vector<CtlPtr> m_ctls;
};

class Win32SystemStoreImpl : public Win32CommonStore
{
  public:
    ~Win32SystemStoreImpl() override = default;

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

  private:
    void deletePrivateKeyContainer(PCCERT_CONTEXT pCert);
    CertStorePtr m_store;
};

class Win32CerFileStore : public Win32FileStore
{
  public:
    StoreType getStoreType() const override { return StoreType::CerFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

  private:
    void saveAsDer(const std::string& location);
    void saveAsPkcs7(const std::string& location);
};

class Win32P7bFileStore : public Win32CerFileStore
{
  public:
    StoreType getStoreType() const override { return StoreType::P7bFile; }
};

class Win32PeFileStore : public Win32FileStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PeFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;
};

class Win32AppxFileStore : public Win32FileStore
{
  public:
    StoreType getStoreType() const override { return StoreType::AppxFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;
};

class Win32PfxCertStore : public Win32FileStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PfxFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

  protected:
    CertificatePtr createCert(CertContextPtr pCert) const override;

  private:
    std::vector<std::unique_ptr<KeySetDeleter>> m_keyDeleters;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_STORE_H
