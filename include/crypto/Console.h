#ifndef CCKY_CRYPTO_CONSOLE_H
#define CCKY_CRYPTO_CONSOLE_H

#include <iosfwd>
#include <string>

namespace ccky
{
namespace crypto
{

class Console
{
  public:
    static std::string askPassword(
        std::istream& in, std::ostream& out, const std::string& prompt = "");

  private:
    static std::string askPasswordStdin(const std::string& prompt);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_CONSOLE_H
