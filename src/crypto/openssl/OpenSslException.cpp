#include "crypto/openssl/OpenSslException.h"

#include <openssl/err.h>

namespace ccky
{
namespace crypto
{

void OpenSslCheck::check(bool condition, const std::string& context)
{
    if (!condition)
    {
        unsigned long err = ERR_get_error();
        std::string msg = context;
        if (err != 0)
        {
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            msg += ": ";
            msg += buf;
        }
        throw OpenSslException(msg);
    }
}

void OpenSslCheck::checkPtr(const void* ptr, const std::string& context)
{
    check(ptr != nullptr, context);
}

} // namespace crypto
} // namespace ccky
