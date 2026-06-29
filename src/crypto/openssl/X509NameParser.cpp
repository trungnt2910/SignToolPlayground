#include "crypto/openssl/X509NameParser.h"
#include "crypto/CckyException.h"
#include <algorithm>
#include <cctype>

namespace ccky
{
namespace crypto
{

namespace
{

std::string trimUnescapedSpaces(const std::string& str)
{
    if (str.empty())
    {
        return str;
    }

    size_t start = 0;
    while (start < str.size() && std::isspace(static_cast<unsigned char>(str[start])))
    {
        start++;
    }

    size_t end = str.size();
    while (end > start)
    {
        // Check if the space is escaped
        if (std::isspace(static_cast<unsigned char>(str[end - 1])))
        {
            bool escaped = false;
            size_t backslashCount = 0;
            for (size_t i = end - 1; i > start; --i)
            {
                if (str[i - 1] == '\\')
                {
                    backslashCount++;
                }
                else
                {
                    break;
                }
            }
            if (backslashCount % 2 != 0)
            {
                // Escaped space, stop trimming
                break;
            }
        }
        else if (!std::isspace(static_cast<unsigned char>(str[end - 1])))
        {
            break;
        }
        end--;
    }

    return str.substr(start, end - start);
}

std::string unescape(const std::string& str)
{
    std::string result;
    result.reserve(str.size());
    bool escaped = false;
    for (char c : str)
    {
        if (escaped)
        {
            result += c;
            escaped = false;
        }
        else if (c == '\\')
        {
            escaped = true;
        }
        else
        {
            result += c;
        }
    }
    if (escaped)
    {
        // Trailing backslash is an error in strict parsing, but we can just treat it as literal or
        // throw.
        throw CckyException("Invalid trailing backslash in DN string", false);
    }
    return result;
}

} // namespace

ParsedX509Name X509NameParser::parse(const std::string& input)
{
    ParsedX509Name result;
    if (input.empty())
    {
        return result;
    }

    RelativeDistinguishedName currentRdn;
    std::string currentKey;
    std::string currentValue;
    bool parsingKey = true;
    bool escaped = false;
    bool expectingComponent = true;

    for (size_t i = 0; i < input.size(); ++i)
    {
        char c = input[i];

        if (escaped)
        {
            if (parsingKey)
            {
                currentKey += '\\'; // Keep the escape char for trim logic
                currentKey += c;
            }
            else
            {
                currentValue += '\\'; // Keep the escape char for trim logic
                currentValue += c;
            }
            escaped = false;
            expectingComponent = false;
        }
        else if (c == '\\')
        {
            escaped = true;
        }
        else if (parsingKey && c == '=')
        {
            parsingKey = false;
        }
        else if (!parsingKey && (c == ',' || c == '+'))
        {
            // Finalize the current attribute
            std::string key = unescape(trimUnescapedSpaces(currentKey));
            std::string value = unescape(trimUnescapedSpaces(currentValue));

            if (key.empty() || value.empty())
            {
                throw CckyException("Empty key or value in DN string: " + input, false);
            }

            currentRdn.push_back({key, value});
            currentKey.clear();
            currentValue.clear();

            if (c == ',')
            {
                result.push_back(currentRdn);
                currentRdn.clear();
            }
            parsingKey = true;
            expectingComponent = true;
        }
        else
        {
            if (parsingKey)
            {
                currentKey += c;
                if (!std::isspace(static_cast<unsigned char>(c)))
                {
                    expectingComponent = false;
                }
            }
            else
            {
                currentValue += c;
            }
        }
    }

    if (escaped)
    {
        throw CckyException("Invalid trailing backslash in DN string: " + input, false);
    }

    if (expectingComponent)
    {
        throw CckyException("Incomplete DN string (trailing separator?): " + input, false);
    }

    if (parsingKey)
    {
        // If we ended in parsingKey, but expectingComponent is false, it means we didn't have
        // trailing separator. But if parsingKey is true, we shouldn't have leftover key.
        if (!currentKey.empty() || !currentRdn.empty())
        {
            throw CckyException("Incomplete DN string: " + input, false);
        }
    }
    else
    {
        // Finalize the last attribute
        std::string key = unescape(trimUnescapedSpaces(currentKey));
        std::string value = unescape(trimUnescapedSpaces(currentValue));

        if (key.empty() || value.empty())
        {
            throw CckyException("Empty key or value in DN string: " + input, false);
        }

        currentRdn.push_back({key, value});
        result.push_back(currentRdn);
    }

    return result;
}

} // namespace crypto
} // namespace ccky
