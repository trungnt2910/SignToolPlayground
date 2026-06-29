#ifndef CCKY_OPENSSL_HELPER_H
#define CCKY_OPENSSL_HELPER_H

#include <string>
#include <vector>

#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

class OpenSslHelper
{
  public:
    static std::string getOpenSslError();
    static std::string getCertCommonName(X509* cert);
    static std::string getCertIssuerName(X509* cert);
    static std::string getNameDisplay(X509_NAME* name);
    static std::string getNameDN(X509_NAME* name);
    static std::string getCertSha1(X509* cert);
    static std::string getCrlSha1(X509_CRL* crl);
    static std::string getBufferSha1(const std::vector<uint8_t>& data);
    static std::string getBufferSha256(const std::vector<uint8_t>& data);

    static std::string getCertSerialNumber(X509* cert);
    static std::string getCertThumbprint(X509* cert, const EVP_MD* md, bool spaceEvery8);
    static std::string getCertKeyMd5Thumbprint(X509* cert);
    static std::string getCertKeySha256Thumbprint(X509* cert);
    static std::string getCertTime(const ASN1_TIME* time);

    static const EVP_MD* getDigestAlgorithm(const std::string& alg);
    static std::string getDigestAlgorithmName(int nid);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_HELPER_H
