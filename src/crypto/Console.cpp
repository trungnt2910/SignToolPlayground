#include "crypto/Console.h"

#include <iostream>
#include <string>

namespace ccky
{
namespace crypto
{

std::string Console::askPassword(std::istream& in, std::ostream& out, const std::string& prompt)
{
    if (&in == &std::cin)
    {
        return askPasswordStdin(prompt);
    }

    // Redirected stream (e.g., in tests)
    out << prompt << std::flush;
    std::string password;
    if (!std::getline(in, password))
    {
        return "";
    }
    return password;
}

} // namespace crypto
} // namespace ccky
