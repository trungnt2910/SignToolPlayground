#include "crypto/Time.h"

#include <string>

#include <windows.h>

#include "crypto/windows/WinHelper.h"

namespace ccky
{
namespace crypto
{

namespace
{
std::wstring s_overrideLocale;
} // namespace

void Time::setLocale(const std::string& lang, const std::string& region)
{
    if (lang.empty() && region.empty())
    {
        s_overrideLocale.clear();
        return;
    }

    std::string tag;
    if (!lang.empty() && !region.empty())
    {
        tag = lang + "-" + region;
    }
    else if (!lang.empty())
    {
        tag = lang;
    }
    else
    {
        tag = region;
    }

    s_overrideLocale = WinHelper::utf8ToWide(tag);
}

void Time::clearLocale() { s_overrideLocale.clear(); }

DateOrder Time::getDateOrder()
{
    DWORD dateOrder = 0;
    LPCWSTR locName =
        s_overrideLocale.empty() ? LOCALE_NAME_USER_DEFAULT : s_overrideLocale.c_str();
    if (GetLocaleInfoEx(locName, LOCALE_IDATE | LOCALE_RETURN_NUMBER,
            reinterpret_cast<LPWSTR>(&dateOrder), sizeof(dateOrder) / sizeof(WCHAR)))
    {
        switch (dateOrder)
        {
        case 0:
            return DateOrder::MonthDayYear;
        case 1:
            return DateOrder::DayMonthYear;
        case 2:
            return DateOrder::YearMonthDay;
        default:
            return DateOrder::Unknown;
        }
    }
    return DateOrder::Unknown;
}

} // namespace crypto
} // namespace ccky
