#ifndef CCKY_TIME_H
#define CCKY_TIME_H

#include <chrono>
#include <string>

namespace ccky
{
namespace crypto
{

enum class DateOrder
{
    Unknown,
    MonthDayYear,
    DayMonthYear,
    YearMonthDay
};

class Time
{
  public:
    static void setFormatUTC(bool formatUTC);
    static bool isFormatUTC();

    static DateOrder getDateOrder();
    static void setLocale(const std::string& lang, const std::string& region);
    static void clearLocale();

    static std::string format(const std::chrono::system_clock::time_point& tp);

    static std::chrono::system_clock::time_point addMonths(
        const std::chrono::system_clock::time_point& tp, int months);

  private:
    static bool s_formatUTC;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_TIME_H
