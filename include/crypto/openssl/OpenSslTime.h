#ifndef CCKY_CRYPTO_OPENSSL_OPENSSL_TIME_H
#define CCKY_CRYPTO_OPENSSL_OPENSSL_TIME_H

#include <chrono>

#include <openssl/asn1.h>

namespace ccky
{
namespace crypto
{

class OpenSslTime
{
  public:
    static std::chrono::system_clock::time_point toChrono(const ASN1_TIME* time);
    static void fromChrono(ASN1_TIME* time, std::chrono::system_clock::time_point tp);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_OPENSSL_OPENSSL_TIME_H
