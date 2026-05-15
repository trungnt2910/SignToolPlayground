#ifndef CCKY_TIME_FORMATTER_H
#define CCKY_TIME_FORMATTER_H

#include <chrono>
#include <string>

namespace ccky
{
namespace crypto
{

class TimeFormatter
{
  public:
    static void setFormatUTC(bool formatUTC);
    static bool isFormatUTC();

    static std::string formatTime(std::chrono::system_clock::time_point tp);

  private:
    static bool s_formatUTC;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_TIME_FORMATTER_H
