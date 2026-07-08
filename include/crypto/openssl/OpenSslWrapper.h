#ifndef CCKY_OPENSSL_WRAPPER_H
#define CCKY_OPENSSL_WRAPPER_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/CckyHandle.h"

namespace ccky
{
namespace crypto
{

struct OpenSslWrapperDeleter
{
    void operator()(STACK_OF(X509) * p) const noexcept { sk_X509_pop_free(p, X509_free); }
    void operator()(EXTENDED_KEY_USAGE* p) const noexcept
    {
        sk_ASN1_OBJECT_pop_free(p, ASN1_OBJECT_free);
    }
    void operator()(CERTIFICATEPOLICIES* p) const noexcept
    {
        sk_POLICYINFO_pop_free(p, POLICYINFO_free);
    }
    void operator()(unsigned char* p) const noexcept { OPENSSL_free(p); }
};

using BIOPtr = CckyHandle<BIO*, BIO_free_all>;
using X509Ptr = CckyHandle<X509*, X509_free, CckyDefault{}, X509_up_ref>;
using X509CRLPtr = CckyHandle<X509_CRL*, X509_CRL_free, CckyDefault{}, X509_CRL_up_ref>;
using X509StackPtr = CckyHandle<STACK_OF(X509)*, OpenSslWrapperDeleter{}>;
using X509ExtensionPtr = CckyHandle<X509_EXTENSION*, X509_EXTENSION_free>;
using EVPPKeyPtr = CckyHandle<EVP_PKEY*, EVP_PKEY_free, CckyDefault{}, EVP_PKEY_up_ref>;
using EVPPKeyCtxPtr = CckyHandle<EVP_PKEY_CTX*, EVP_PKEY_CTX_free>;
using PKCS7Ptr = CckyHandle<PKCS7*, PKCS7_free>;
using PKCS12Ptr = CckyHandle<PKCS12*, PKCS12_free>;
using PolicyInfoPtr = CckyHandle<POLICYINFO*, POLICYINFO_free>;
using PolicyQualInfoPtr = CckyHandle<POLICYQUALINFO*, POLICYQUALINFO_free>;
using EVPMDCtxPtr = CckyHandle<EVP_MD_CTX*, EVP_MD_CTX_free>;
using BNPtr = CckyHandle<BIGNUM*, BN_free>;
using EKUPtr = CckyHandle<EXTENDED_KEY_USAGE*, OpenSslWrapperDeleter{}>;
using ASN1BitStringPtr = CckyHandle<ASN1_BIT_STRING*, ASN1_BIT_STRING_free>;
using ASN1ObjectPtr = CckyHandle<ASN1_OBJECT*, ASN1_OBJECT_free>;
using ASN1OctetStringPtr = CckyHandle<ASN1_OCTET_STRING*, ASN1_OCTET_STRING_free>;
using CertificatePoliciesPtr = CckyHandle<CERTIFICATEPOLICIES*, OpenSslWrapperDeleter{}>;
using OpenSslBufferPtr = CckyHandle<unsigned char*, OpenSslWrapperDeleter{}>;
using OsslParamBldPtr = CckyHandle<OSSL_PARAM_BLD*, OSSL_PARAM_BLD_free>;
using OsslParamPtr = CckyHandle<OSSL_PARAM*, OSSL_PARAM_free>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_WRAPPER_H
