#include "crypto/windows/Win32Exception.h"

#include <format>

#include <windows.h>

#include "crypto/windows/Win32Helper.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

std::string Win32Check::buildMessage(const std::string& context)
{
    DWORD err = GetLastError();
    LocalFreePtr<WCHAR> buf;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf.init()), 0, nullptr);
    std::string msg = std::format("{} (Error {})", context, err);
    if (buf.get())
    {
        msg += ": " + Win32Helper::wideToUtf8(buf.get());
    }
    return msg;
}

std::string Win32Check::buildHrMessage(long hr, const std::string& context)
{
    DWORD err = static_cast<DWORD>(hr);
    LocalFreePtr<WCHAR> buf;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf.init()), 0, nullptr);
    std::string msg = std::format("{} (HRESULT {})", context, hr);
    if (buf.get())
    {
        msg += ": " + Win32Helper::wideToUtf8(buf.get());
    }
    return msg;
}

std::string Win32Check::buildStatusMessage(long status, const std::string& context)
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
        msg += ": " + Win32Helper::wideToUtf8(buf.get());
    }
    return msg;
}

} // namespace crypto
} // namespace ccky
