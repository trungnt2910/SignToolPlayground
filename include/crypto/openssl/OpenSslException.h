#ifndef CCKY_OPENSSL_EXCEPTION_H
#define CCKY_OPENSSL_EXCEPTION_H

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

class OpenSslException : public CckyCryptoException
{
  public:
    explicit OpenSslException(const std::string& what_arg, bool printHelp = false)
        : CckyCryptoException(what_arg, printHelp)
    {
    }
};

class OpenSslCheck
{
  public:
    static void check(bool condition, const std::string& context);
    static void checkPtr(const void* ptr, const std::string& context);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_EXCEPTION_H
