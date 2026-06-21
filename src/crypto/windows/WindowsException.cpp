#include "crypto/windows/WindowsException.h"

#include <windows.h>

namespace ccky
{
namespace crypto
{

void Win32Check::check(bool condition, const std::string& context)
{
    if (!condition)
    {
        DWORD err = GetLastError();
        LPWSTR buf = nullptr;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buf),
            0, nullptr);
        std::string msg = context;
        if (buf)
        {
            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (sizeNeeded > 0)
            {
                std::string utf8Msg(sizeNeeded - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, &utf8Msg[0], sizeNeeded, nullptr, nullptr);
                msg += ": " + utf8Msg;
            }
            LocalFree(buf);
        }
        else
        {
            msg += ": Error code " + std::to_string(err);
        }
        throw WindowsException(msg);
    }
}

void Win32Check::checkPtr(const void* ptr, const std::string& context)
{
    check(ptr != nullptr && ptr != INVALID_HANDLE_VALUE, context);
}

void Win32Check::checkHr(long hr, const std::string& context)
{
    if (hr < 0)
    {
        DWORD err = static_cast<DWORD>(hr);
        LPWSTR buf = nullptr;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buf),
            0, nullptr);
        std::string msg = context + " (HRESULT " + std::to_string(hr) + ")";
        if (buf)
        {
            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (sizeNeeded > 0)
            {
                std::string utf8Msg(sizeNeeded - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, &utf8Msg[0], sizeNeeded, nullptr, nullptr);
                msg += ": " + utf8Msg;
            }
            LocalFree(buf);
        }
        throw WindowsException(msg);
    }
}

} // namespace crypto
} // namespace ccky
