#include "crypto/windows/Win32Time.h"

#include "crypto/windows/Win32Exception.h"

namespace ccky
{
namespace crypto
{

std::chrono::system_clock::time_point Win32Time::toChrono(const FILETIME& ft)
{
    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));
    Win32Check::check(FileTimeToSystemTime(&ft, &st), "Failed to convert FILETIME to SYSTEMTIME");

    std::chrono::year_month_day ymd{
        std::chrono::year{st.wYear}, std::chrono::month{st.wMonth}, std::chrono::day{st.wDay}};
    std::chrono::sys_days sysDays = ymd;
    return sysDays + std::chrono::hours{st.wHour} + std::chrono::minutes{st.wMinute} +
           std::chrono::seconds{st.wSecond} + std::chrono::milliseconds{st.wMilliseconds};
}

FILETIME Win32Time::fromChrono(std::chrono::system_clock::time_point tp)
{
    auto sysDays = std::chrono::floor<std::chrono::days>(tp);
    auto tod = tp - sysDays;
    std::chrono::year_month_day ymd{sysDays};

    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));
    st.wYear = static_cast<WORD>(static_cast<int>(ymd.year()));
    st.wMonth = static_cast<WORD>(static_cast<unsigned>(ymd.month()));
    st.wDay = static_cast<WORD>(static_cast<unsigned>(ymd.day()));
    auto hrs = std::chrono::duration_cast<std::chrono::hours>(tod);
    st.wHour = static_cast<WORD>(hrs.count());
    tod -= hrs;
    auto mins = std::chrono::duration_cast<std::chrono::minutes>(tod);
    st.wMinute = static_cast<WORD>(mins.count());
    tod -= mins;
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(tod);
    st.wSecond = static_cast<WORD>(secs.count());
    tod -= secs;
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(tod);
    st.wMilliseconds = static_cast<WORD>(millis.count());

    FILETIME ft;
    Win32Check::check(SystemTimeToFileTime(&st, &ft), "Failed to convert SYSTEMTIME to FILETIME");
    return ft;
}

} // namespace crypto
} // namespace ccky
