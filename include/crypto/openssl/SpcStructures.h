#ifndef CCKY_CRYPTO_OPENSSL_SPCSTRUCTURES_H
#define CCKY_CRYPTO_OPENSSL_SPCSTRUCTURES_H

#include <memory>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#define OID_SPC_SP_AGENCY_INFO "1.3.6.1.4.1.311.2.1.10"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct SpcSpAgencyInfo_st
    {
        ASN1_IA5STRING* policyInformation;
        // We omit other fields since we don't use them and they are optional.
    } SPC_SP_AGENCY_INFO;

    DECLARE_ASN1_FUNCTIONS(SPC_SP_AGENCY_INFO)

#ifdef __cplusplus
}
#endif

namespace ccky
{
namespace crypto
{
struct SPC_SP_AGENCY_INFO_Deleter
{
    void operator()(SPC_SP_AGENCY_INFO* p) const { SPC_SP_AGENCY_INFO_free(p); }
};
using SpcSpAgencyInfoPtr = std::unique_ptr<SPC_SP_AGENCY_INFO, SPC_SP_AGENCY_INFO_Deleter>;
} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_OPENSSL_SPCSTRUCTURES_H
