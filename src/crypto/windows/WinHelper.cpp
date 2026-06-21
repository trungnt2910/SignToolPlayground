#include "crypto/windows/WinHelper.h"

#include <windows.h>

#include "crypto/windows/WindowsException.h"

namespace ccky
{
namespace crypto
{

std::wstring WinHelper::utf8ToWide(const std::string& utf8Str)
{
    if (utf8Str.empty())
    {
        return L"";
    }
    int sizeNeeded = MultiByteToWideChar(
        CP_UTF8, 0, utf8Str.c_str(), static_cast<int>(utf8Str.size()), nullptr, 0);
    if (sizeNeeded <= 0)
    {
        throw WindowsException("Failed to convert UTF-8 string to wide string.");
    }
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(
        CP_UTF8, 0, utf8Str.c_str(), static_cast<int>(utf8Str.size()), &wstr[0], sizeNeeded);
    return wstr;
}

std::string WinHelper::wideToUtf8(const std::wstring& wideStr)
{
    if (wideStr.empty())
    {
        return "";
    }
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(),
        static_cast<int>(wideStr.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0)
    {
        throw WindowsException("Failed to convert wide string to UTF-8 string.");
    }
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), static_cast<int>(wideStr.size()), &str[0],
        sizeNeeded, nullptr, nullptr);
    return str;
}

} // namespace crypto
} // namespace ccky
