#include "crypto/openssl/OpenSslException.h"

#include <openssl/err.h>

namespace ccky
{
namespace crypto
{

std::string OpenSslCheck::buildMessage(const std::string& context)
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
    return msg;
}

} // namespace crypto
} // namespace ccky
