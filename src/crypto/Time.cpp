#include "crypto/Time.h"

#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

bool Time::s_formatUTC = false;

void Time::setFormatUTC(bool formatUTC) { s_formatUTC = formatUTC; }
bool Time::isFormatUTC() { return s_formatUTC; }

std::string Time::format(const std::chrono::system_clock::time_point& tp)
{
    time_t time = std::chrono::system_clock::to_time_t(tp);
    struct tm* tPtr = s_formatUTC ? std::gmtime(&time) : std::localtime(&time);
    if (!tPtr)
    {
        return "";
    }
    std::stringstream ss;
    ss << std::put_time(tPtr, "%a %b %d %H:%M:%S %Y");
    return ss.str();
}

std::chrono::system_clock::time_point Time::addMonths(
    const std::chrono::system_clock::time_point& tp, int months)
{
    std::chrono::year_month_day ymd;
    struct tm t = {};
    if (isFormatUTC())
    {
        auto startDays = std::chrono::floor<std::chrono::days>(tp);
        ymd = std::chrono::year_month_day{startDays};
    }
    else
    {
        time_t st_time = std::chrono::system_clock::to_time_t(tp);
        t = *std::localtime(&st_time);
        ymd = std::chrono::year_month_day{std::chrono::year{t.tm_year + 1900},
            std::chrono::month{static_cast<unsigned>(t.tm_mon + 1)},
            std::chrono::day{static_cast<unsigned>(t.tm_mday)}};
    }

    auto target_ym = (ymd.year() / ymd.month()) + std::chrono::months(months);
    std::chrono::year_month_day ymd_target = target_ym / ymd.day();
    if (!ymd_target.ok())
    {
        ymd_target = target_ym / std::chrono::last;
    }

    if (isFormatUTC())
    {
        auto startDays = std::chrono::floor<std::chrono::days>(tp);
        std::chrono::sys_days targetDays = ymd_target;
        return targetDays + (tp - startDays);
    }
    else
    {
        t.tm_year = static_cast<int>(ymd_target.year()) - 1900;
        t.tm_mon = static_cast<unsigned>(ymd_target.month()) - 1;
        t.tm_mday = static_cast<unsigned>(ymd_target.day());
        t.tm_isdst = -1;
        time_t end_time = std::mktime(&t);
        return std::chrono::system_clock::from_time_t(end_time);
    }
}

} // namespace crypto
} // namespace ccky
