#ifndef CCKY_CERTIFICATE_H
#define CCKY_CERTIFICATE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ccky
{
namespace crypto
{

class Certificate
{
  public:
    virtual ~Certificate() = default;

    virtual std::string getCommonName() const = 0;
    virtual std::string getIssuerName() const = 0;
    virtual std::string getSha1() const = 0;
    virtual std::vector<uint8_t> getEncoded() const = 0;

    virtual std::string getSubjectDisplay() const = 0;
    virtual std::string getIssuerDisplay() const = 0;
    virtual std::string getSerialNumber() const = 0;
    virtual std::string getSha1Thumbprint() const = 0;
    virtual std::string getMd5Thumbprint() const = 0;
    virtual std::string getKeyMd5Thumbprint() const = 0;
    virtual std::string getProviderType() const = 0;
    virtual std::string getProviderName() const = 0;
    virtual std::string getContainerName() const = 0;
    virtual std::string getNotBefore() const = 0;
    virtual std::string getNotAfter() const = 0;
};

using CertificatePtr = std::shared_ptr<Certificate>;

class Crl
{
  public:
    virtual ~Crl() = default;

    virtual std::string getSha1() const = 0;
    virtual std::vector<uint8_t> getEncoded() const = 0;
};

using CrlPtr = std::shared_ptr<Crl>;

class Ctl
{
  public:
    virtual ~Ctl() = default;

    virtual std::string getSha1() const = 0;
    virtual std::vector<uint8_t> getEncoded() const = 0;
};

using CtlPtr = std::shared_ptr<Ctl>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_CERTIFICATE_H
