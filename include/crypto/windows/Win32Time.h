#ifndef CCKY_CRYPTO_WINDOWS_WIN32_TIME_H
#define CCKY_CRYPTO_WINDOWS_WIN32_TIME_H

#include <chrono>

#include <windows.h>

namespace ccky
{
namespace crypto
{

class Win32Time
{
  public:
    static std::chrono::system_clock::time_point toChrono(const FILETIME& ft);
    static FILETIME fromChrono(std::chrono::system_clock::time_point tp);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_WINDOWS_WIN32_TIME_H
