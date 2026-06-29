#include "crypto/Console.h"

#include <openssl/ui.h>

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

std::string Console::askPasswordStdin(const std::string& prompt)
{
    char result[4096] = {0};
    if (EVP_read_pw_string(result, sizeof(result) - 1, prompt.c_str(), 0) != 0)
    {
        throw CckyException("Failed to read password", false);
    }
    return result;
}

} // namespace crypto
} // namespace ccky
