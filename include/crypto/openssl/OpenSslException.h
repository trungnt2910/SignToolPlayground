#ifndef CCKY_OPENSSL_EXCEPTION_H
#define CCKY_OPENSSL_EXCEPTION_H

#include <utility>

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
    template <typename E = OpenSslException>
    static void check(bool condition, const std::string& context)
    {
        if (!condition)
        {
            throw E(buildMessage(context));
        }
    }
    template <typename E = OpenSslException, typename T>
    static T* checkPtr(T* ptr, const std::string& context)
    {
        check<E>(ptr != nullptr, context);
        return ptr;
    }
    // Validates a CckyHandle (or any handle exposing isValid()) without requiring
    // the caller to reach for the underlying pointer via a manual != nullptr check.
    template <typename E = OpenSslException, typename Handle>
    static Handle&& checkHandle(Handle&& handle, const std::string& context)
        requires requires { handle.isValid(); }
    {
        check<E>(handle.isValid(), context);
        return std::forward<Handle>(handle);
    }

  private:
    // Appends the current OpenSSL error (ERR_get_error) to context, if any.
    static std::string buildMessage(const std::string& context);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_OPENSSL_EXCEPTION_H
