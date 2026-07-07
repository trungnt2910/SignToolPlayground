#include "crypto/Time.h"

#include <cstring>
#include <ctime>
#include <iomanip>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

namespace ccky
{
namespace crypto
{

namespace
{
std::string s_overrideLocale;
} // namespace

void Time::setLocale(const std::string& lang, const std::string& region)
{
    if (lang.empty() && region.empty())
    {
        s_overrideLocale.clear();
        return;
    }

    std::vector<std::string> candidates;
    if (!lang.empty() && !region.empty())
    {
        candidates.push_back(lang + "_" + region + ".utf8");
        candidates.push_back(lang + "_" + region + ".UTF-8");
        candidates.push_back(lang + "-" + region);
        candidates.push_back(lang + "_" + region);
    }
    else if (!lang.empty())
    {
        candidates.push_back(lang + ".utf8");
        candidates.push_back(lang);
    }
    else
    {
        candidates.push_back(region);
    }

    for (const auto& cand : candidates)
    {
        try
        {
            std::locale testLoc(cand);
            s_overrideLocale = cand;
            return;
        }
        catch (...)
        {
        }
    }
    if (!candidates.empty())
    {
        s_overrideLocale = candidates.front();
    }
}

void Time::clearLocale() { s_overrideLocale.clear(); }

DateOrder Time::getDateOrder()
{
    std::locale loc;
    if (!s_overrideLocale.empty())
    {
        try
        {
            loc = std::locale(s_overrideLocale);
        }
        catch (...)
        {
        }
    }

    struct tm tm = {};
    tm.tm_year = 2023 - 1900;
    tm.tm_mon = 11;  // 11 = December (Month 12)
    tm.tm_mday = 11; // Day 11

    std::ostringstream oss;
    oss.imbue(loc);
    oss << std::put_time(&tm, "%x");
    std::string formatted = oss.str();

    size_t posDay = formatted.find("11");
    size_t posMonth = formatted.find("12");
    size_t posYear = formatted.find("2023");
    if (posYear == std::string::npos)
    {
        posYear = formatted.find("23");
    }

    if (posDay == std::string::npos || posMonth == std::string::npos ||
        posYear == std::string::npos)
    {
        return DateOrder::Unknown;
    }

    if (posYear < posMonth && posYear < posDay)
    {
        return DateOrder::YearMonthDay;
    }
    if (posMonth < posDay)
    {
        return DateOrder::MonthDayYear;
    }
    return DateOrder::DayMonthYear;
}

} // namespace crypto
} // namespace ccky
