#ifndef CCKY_CRYPTO_OPENSSL_X509NAMEPARSER_H
#define CCKY_CRYPTO_OPENSSL_X509NAMEPARSER_H

#include <string>
#include <vector>

namespace ccky
{
namespace crypto
{

struct RdnAttribute
{
    std::string key;
    std::string value;
};

using RelativeDistinguishedName = std::vector<RdnAttribute>;
using ParsedX509Name = std::vector<RelativeDistinguishedName>;

class X509NameParser
{
  public:
    // Parses an X.500 / RFC 2253 DN string.
    // Supports ',' as RDN separator, '+' as multi-valued RDN separator, and '=' as key-value
    // separator. Supports '\' for escaping separators and itself. Throws CckyException on syntax
    // errors.
    static ParsedX509Name parse(const std::string& input);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_OPENSSL_X509NAMEPARSER_H
