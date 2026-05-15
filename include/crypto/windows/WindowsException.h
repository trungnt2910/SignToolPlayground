#ifndef CCKY_WINDOWS_EXCEPTION_H
#define CCKY_WINDOWS_EXCEPTION_H

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

class WindowsException : public CckyCryptoException
{
  public:
    explicit WindowsException(const std::string& what_arg, bool printHelp = false)
        : CckyCryptoException(what_arg, printHelp)
    {
    }
};

class Win32Check
{
  public:
    static void check(bool condition, const std::string& context);
    static void checkPtr(const void* ptr, const std::string& context);
    static void checkHr(long hr, const std::string& context);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WINDOWS_EXCEPTION_H
