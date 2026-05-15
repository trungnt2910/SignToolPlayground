#ifndef CCKY_WIN_STORE_H
#define CCKY_WIN_STORE_H

#include <memory>
#include <string>
#include <vector>

#include <windows.h>

#include <wincrypt.h>

#include "crypto/ICertStore.h"
#include "crypto/windows/WinCert.h"

namespace ccky
{
namespace crypto
{

class Win32CommonStore : public ICertStore
{
  public:
    ~Win32CommonStore() override = default;

    StoreType getStoreType() const override = 0;
    void load(const std::string& location, const StoreOptions& options = {}) override = 0;
    void save(const std::string& location, const StoreOptions& options = {}) override = 0;

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

  protected:
    virtual CertificatePtr createCert(PCCERT_CONTEXT pCert) const;
    void populateFromStore(HCERTSTORE hStore);

    std::string m_loadedLocation;
    std::vector<CertificatePtr> m_certs;
    std::vector<CrlPtr> m_crls;
    std::vector<CtlPtr> m_ctls;
    std::string m_signingAlgorithm;
    std::string m_timestamp;
};

class WinSystemStoreImpl : public ICertStore
{
  public:
    ~WinSystemStoreImpl() override = default;

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

  private:
    CertStorePtr m_store;
    std::string m_loadedLocation;
};

class WinCerFileStore : public Win32CommonStore
{
  public:
    StoreType getStoreType() const override { return StoreType::CerFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;
};

class WinPeFileStore : public Win32CommonStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PeFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;
};

class WinPfxCertStore : public Win32CommonStore
{
  public:
    StoreType getStoreType() const override { return StoreType::PfxFile; }
    void load(const std::string& location, const StoreOptions& options = {}) override;
    void save(const std::string& location, const StoreOptions& options = {}) override;

  protected:
    CertificatePtr createCert(PCCERT_CONTEXT pCert) const override;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN_STORE_H
