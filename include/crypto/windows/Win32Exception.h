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
    template <typename E = Win32Exception>
    static void check(bool condition, const std::string& context)
    {
        if (!condition)
        {
            throw E(buildMessage(context));
        }
    }
    template <typename E = Win32Exception, typename T>
    static T* checkPtr(T* ptr, const std::string& context)
    {
        check<E>(ptr != nullptr && ptr != INVALID_HANDLE_VALUE, context);
        return ptr;
    }
    template <typename E = Win32Exception> static void checkHr(long hr, const std::string& context)
    {
        if (hr < 0)
        {
            throw E(buildHrMessage(hr, context));
        }
    }
    template <typename E = Win32Exception>
    static void checkStatus(long status, const std::string& context)
    {
        if (status < 0)
        {
            throw E(buildStatusMessage(status, context));
        }
    }

  private:
    // Appends the current Win32 error (GetLastError) to context, if any.
    static std::string buildMessage(const std::string& context);
    // Appends the HRESULT and its system message to context.
    static std::string buildHrMessage(long hr, const std::string& context);
    // Appends the NTSTATUS and its ntdll message to context.
    static std::string buildStatusMessage(long status, const std::string& context);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_EXCEPTION_H
