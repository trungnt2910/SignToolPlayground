#include "crypto/TimeFormatter.h"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace ccky
{
namespace crypto
{

bool TimeFormatter::s_formatUTC = false;

void TimeFormatter::setFormatUTC(bool formatUTC) { s_formatUTC = formatUTC; }
bool TimeFormatter::isFormatUTC() { return s_formatUTC; }

std::string TimeFormatter::formatTime(std::chrono::system_clock::time_point tp)
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

} // namespace crypto
} // namespace ccky
