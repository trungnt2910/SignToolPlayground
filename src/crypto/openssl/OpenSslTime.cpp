#include "crypto/openssl/OpenSslTime.h"

#include <cstring>
#include <ctime>

#include "crypto/openssl/OpenSslException.h"

namespace ccky
{
namespace crypto
{

std::chrono::system_clock::time_point OpenSslTime::toChrono(const ASN1_TIME* time)
{
    struct tm t;
    std::memset(&t, 0, sizeof(t));
    OpenSslCheck::check(ASN1_TIME_to_tm(time, &t), "Failed to convert ASN1_TIME to tm");

    std::chrono::year_month_day ymd{std::chrono::year{t.tm_year + 1900},
        std::chrono::month{static_cast<unsigned>(t.tm_mon + 1)},
        std::chrono::day{static_cast<unsigned>(t.tm_mday)}};
    std::chrono::sys_days sysDays = ymd;
    return sysDays + std::chrono::hours{t.tm_hour} + std::chrono::minutes{t.tm_min} +
           std::chrono::seconds{t.tm_sec};
}

void OpenSslTime::fromChrono(ASN1_TIME* time, std::chrono::system_clock::time_point tp)
{
    time_t t = std::chrono::system_clock::to_time_t(tp);
    OpenSslCheck::checkPtr(ASN1_TIME_set(time, t), "Failed to set ASN1_TIME from time_t");
}

} // namespace crypto
} // namespace ccky
