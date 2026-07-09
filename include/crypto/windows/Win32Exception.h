#ifndef CCKY_WIN32_EXCEPTION_H
#define CCKY_WIN32_EXCEPTION_H

#include <windows.h>

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

class Win32Exception : public CckyCryptoException
{
  public:
    explicit Win32Exception(const std::string& what_arg, bool printHelp = false)
        : CckyCryptoException(what_arg, printHelp)
    {
    }
};

class Win32Check
{
  public:
    static void check(bool condition, const std::string& context);
    template <typename T> static T* checkPtr(T* ptr, const std::string& context)
    {
        check(ptr != nullptr && ptr != INVALID_HANDLE_VALUE, context);
        return ptr;
    }
    static void checkHr(long hr, const std::string& context);
    static void checkStatus(long status, const std::string& context);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_EXCEPTION_H
