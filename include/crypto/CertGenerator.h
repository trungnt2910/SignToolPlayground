#ifndef CCKY_CRYPTO_CERT_GENERATOR_H
#define CCKY_CRYPTO_CERT_GENERATOR_H

#include <functional>
#include <string>
#include <vector>

#include "crypto/PrivateKey.h"

namespace ccky
{
namespace crypto
{

struct MakeCertOptions
{
    std::string subjectName;
    std::string outputCertFile;
    bool selfSigned;
    std::string pvkFile;
    std::string keyContainer;
    std::string startStr;
    std::string endStr;
    int months;
    std::string algo;
    int keyLen;
    int keySpec;
    std::string ssStoreName;
    std::string srStoreLocation;
    std::string spProviderName;
    int syProviderType;
    bool exportable;
    std::string cyCertType;
    int pathLen;
    bool hasPathLen;
    bool hasStoreOptions;
    long serialNum;
    bool hasSerialNum;
    bool hasIssuerCert;
    std::function<std::string()> createPasswordCallback;
    std::function<std::string()> openPasswordCallback;
    std::string issuerCertFile;
    std::string issuerPvkFile;
    std::string issuerKeyContainer;
    int issuerKeySpec;
    std::function<std::string()> openIssuerPasswordCallback;
    std::string issuerName;
    std::string issuerStoreName;
    std::string issuerStoreLocation;
    std::vector<std::string> ekuOids;
    std::string subjectCertFile;
    std::string policyLink;
    bool netscape;
    std::string authority;
};

class CertGenerator
{
  public:
    static PrivateKeyPtr loadSubjectKey(const MakeCertOptions& options);
    static PrivateKeyPtr generateSubjectKey(const MakeCertOptions& options);
    static void generateCertificate(const MakeCertOptions& options, PrivateKeyPtr subjectKey);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_CERT_GENERATOR_H
