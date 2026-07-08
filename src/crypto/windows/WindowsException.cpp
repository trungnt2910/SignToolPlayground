#include "crypto/windows/WindowsException.h"

#include <format>

#include <windows.h>

#include "crypto/windows/Win32Wrapper.h"
#include "crypto/windows/WinHelper.h"

namespace ccky
{
namespace crypto
{

void Win32Check::check(bool condition, const std::string& context)
{
    if (!condition)
    {
        DWORD err = GetLastError();
        LocalFreePtr<WCHAR> buf;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buf.init()), 0, nullptr);
        std::string msg = std::format("{} (Error {})", context, err);
        if (buf.get())
        {
            msg += ": " + WinHelper::wideToUtf8(buf.get());
        }
        throw WindowsException(msg);
    }
}

void Win32Check::checkHr(long hr, const std::string& context)
{
    if (hr < 0)
    {
        DWORD err = static_cast<DWORD>(hr);
        LocalFreePtr<WCHAR> buf;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buf.init()), 0, nullptr);
        std::string msg = std::format("{} (HRESULT {})", context, hr);
        if (buf.get())
        {
            msg += ": " + WinHelper::wideToUtf8(buf.get());
        }
        throw WindowsException(msg);
    }
}

void Win32Check::checkStatus(long status, const std::string& context)
{
    if (status < 0)
    {
        DWORD err = static_cast<DWORD>(status);
        LocalFreePtr<WCHAR> buf;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
            GetModuleHandleW(L"ntdll.dll"), err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buf.init()), 0, nullptr);
        std::string msg = std::format("{} (NTSTATUS 0x{:08x})", context, err);
        if (buf.get())
        {
            msg += ": " + WinHelper::wideToUtf8(buf.get());
        }
        throw WindowsException(msg);
    }
}

} // namespace crypto
} // namespace ccky
