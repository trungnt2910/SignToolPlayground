#ifndef CCKY_WIN_HELPER_H
#define CCKY_WIN_HELPER_H

#include <string>

namespace ccky
{
namespace crypto
{

class WinHelper
{
  public:
    static std::wstring utf8ToWide(const std::string& utf8Str);
    static std::string wideToUtf8(const std::wstring& wideStr);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN_HELPER_H
