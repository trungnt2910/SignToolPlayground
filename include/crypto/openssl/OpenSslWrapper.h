#ifndef CCKY_OPENSSL_WRAPPER_H
#define CCKY_OPENSSL_WRAPPER_H

#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace ccky
{
namespace crypto
{

struct BIO_Deleter
{
    void operator()(BIO* p) const { BIO_free_all(p); }
};
struct X509_Deleter
{
    void operator()(X509* p) const { X509_free(p); }
};
struct X509_CRL_Deleter
{
    void operator()(X509_CRL* p) const { X509_CRL_free(p); }
};
struct EVP_PKEY_Deleter
{
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct PKCS7_Deleter
{
    void operator()(PKCS7* p) const { PKCS7_free(p); }
};
struct PKCS12_Deleter
{
    void operator()(PKCS12* p) const { PKCS12_free(p); }
};
struct EVP_MD_CTX_Deleter
{
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};

using BIOPtr = std::unique_ptr<BIO, BIO_Deleter>;
using X509Ptr = std::unique_ptr<X509, X509_Deleter>;
using X509CRLPtr = std::unique_ptr<X509_CRL, X509_CRL_Deleter>;
using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using PKCS7Ptr = std::unique_ptr<PKCS7, PKCS7_Deleter>;
using PKCS12Ptr = std::unique_ptr<PKCS12, PKCS12_Deleter>;
using EVPMDCtxPtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

class OpenSslHelper
{
  public:
    static std::string getOpenSslError();
    static std::string getCertCommonName(X509* cert);
    static std::string getCertIssuerName(X509* cert);
    static std::string getNameDisplay(X509_NAME* name);
    static std::string getCertSha1(X509* cert);
    static std::string getCrlSha1(X509_CRL* crl);
    static std::string getBufferSha1(const std::vector<uint8_t>& data);
    static std::string getBufferSha256(const std::vector<uint8_t>& data);

    static std::string getCertSerialNumber(X509* cert);
    static std::string getCertThumbprint(X509* cert, const EVP_MD* md, bool spaceEvery8);
    static std::string getCertKeyMd5Thumbprint(X509* cert);
    static std::string getCertTime(const ASN1_TIME* time);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_WRAPPER_H
