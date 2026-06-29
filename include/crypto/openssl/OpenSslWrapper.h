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
struct X509_STACK_Deleter
{
    void operator()(STACK_OF(X509) * p) const { sk_X509_pop_free(p, X509_free); }
};
struct X509_EXTENSION_Deleter
{
    void operator()(X509_EXTENSION* p) const { X509_EXTENSION_free(p); }
};
struct EVP_PKEY_Deleter
{
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct EVP_PKEY_CTX_Deleter
{
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct PKCS7_Deleter
{
    void operator()(PKCS7* p) const { PKCS7_free(p); }
};
struct PKCS12_Deleter
{
    void operator()(PKCS12* p) const { PKCS12_free(p); }
};
struct POLICYINFO_Deleter
{
    void operator()(POLICYINFO* p) const { POLICYINFO_free(p); }
};
struct POLICYQUALINFO_Deleter
{
    void operator()(POLICYQUALINFO* p) const { POLICYQUALINFO_free(p); }
};
struct EVP_MD_CTX_Deleter
{
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct BIGNUM_Deleter
{
    void operator()(BIGNUM* p) const { BN_free(p); }
};
struct EKU_Deleter
{
    void operator()(EXTENDED_KEY_USAGE* p) const { sk_ASN1_OBJECT_pop_free(p, ASN1_OBJECT_free); }
};
struct ASN1_BIT_STRING_Deleter
{
    void operator()(ASN1_BIT_STRING* p) const { ASN1_BIT_STRING_free(p); }
};
struct ASN1_OBJECT_Deleter
{
    void operator()(ASN1_OBJECT* p) const { ASN1_OBJECT_free(p); }
};
struct ASN1_OCTET_STRING_Deleter
{
    void operator()(ASN1_OCTET_STRING* p) const { ASN1_OCTET_STRING_free(p); }
};
struct CertificatePolicies_Deleter
{
    void operator()(CERTIFICATEPOLICIES* p) const { sk_POLICYINFO_pop_free(p, POLICYINFO_free); }
};
struct OpenSslFree_Deleter
{
    void operator()(void* p) const { OPENSSL_free(p); }
};

using BIOPtr = std::unique_ptr<BIO, BIO_Deleter>;
using X509Ptr = std::unique_ptr<X509, X509_Deleter>;
using X509CRLPtr = std::unique_ptr<X509_CRL, X509_CRL_Deleter>;
using X509StackPtr = std::unique_ptr<STACK_OF(X509), X509_STACK_Deleter>;
using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, X509_EXTENSION_Deleter>;
using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using EVPPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using PKCS7Ptr = std::unique_ptr<PKCS7, PKCS7_Deleter>;
using PKCS12Ptr = std::unique_ptr<PKCS12, PKCS12_Deleter>;
using PolicyInfoPtr = std::unique_ptr<POLICYINFO, POLICYINFO_Deleter>;
using PolicyQualInfoPtr = std::unique_ptr<POLICYQUALINFO, POLICYQUALINFO_Deleter>;
using EVPMDCtxPtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;
using BNPtr = std::unique_ptr<BIGNUM, BIGNUM_Deleter>;
using EKUPtr = std::unique_ptr<EXTENDED_KEY_USAGE, EKU_Deleter>;
using ASN1BitStringPtr = std::unique_ptr<ASN1_BIT_STRING, ASN1_BIT_STRING_Deleter>;
using ASN1ObjectPtr = std::unique_ptr<ASN1_OBJECT, ASN1_OBJECT_Deleter>;
using ASN1OctetStringPtr = std::unique_ptr<ASN1_OCTET_STRING, ASN1_OCTET_STRING_Deleter>;
using CertificatePoliciesPtr = std::unique_ptr<CERTIFICATEPOLICIES, CertificatePolicies_Deleter>;
using OpenSslBufferPtr = std::unique_ptr<unsigned char, OpenSslFree_Deleter>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_WRAPPER_H
