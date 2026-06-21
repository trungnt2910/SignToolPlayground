#ifndef CCKY_I_CERT_STORE_H
#define CCKY_I_CERT_STORE_H

#include <memory>
#include <string>
#include <vector>

#include "crypto/Certificate.h"

namespace ccky
{
namespace crypto
{

enum class StoreType
{
    CerFile,
    PeFile,
    AppxFile,
    PfxFile,
    WinSystem
};

struct StoreOptions
{
    std::string registryLocation; // /r (currentUser, localMachine)
    std::string providerName;     // /y
    std::string encodingType;     // /e
    std::string password;         // /p
};

class ICertStore
{
  public:
    virtual ~ICertStore() = default;

    virtual StoreType getStoreType() const = 0;
    virtual void load(const std::string& location, const StoreOptions& options = {}) = 0;
    virtual void save(const std::string& location, const StoreOptions& options = {}) = 0;

    virtual std::string getSigningAlgorithm() = 0;
    virtual std::string getTimestamp() = 0;

    virtual std::vector<CertificatePtr> getCertificates() = 0;
    virtual std::vector<CrlPtr> getCrls() = 0;
    virtual std::vector<CtlPtr> getCtls() = 0;

    virtual void addCertificate(CertificatePtr cert) = 0;
    virtual void addCrl(CrlPtr crl) = 0;
    virtual void addCtl(CtlPtr ctl) = 0;

    virtual void deleteCertificate(const std::string& commonName, const std::string& sha1Hash) = 0;
    virtual void deleteCrl(const std::string& sha1Hash) = 0;
    virtual void deleteCtl(const std::string& sha1Hash) = 0;

    virtual void addPrivateKey(
        const std::string& pfxFilePath, const std::string& password = "") = 0;
    virtual void deletePrivateKey(const std::string& commonName, const std::string& sha1Hash) = 0;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_I_CERT_STORE_H
