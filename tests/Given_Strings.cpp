#include "crypto/Strings.h"

#include <string>

#include <gtest/gtest.h>

using namespace ccky::crypto;

TEST(Given_Strings, When_ToLowerWithMixedCase_ReturnsAllLowerCase)
{
    std::string input = "Hello, WORLD 123!";

    std::string result = Strings::toLower(input);

    EXPECT_EQ("hello, world 123!", result);
}

TEST(Given_Strings, When_ToUpperWithMixedCase_ReturnsAllUpperCase)
{
    std::string input = "Hello, world 123!";

    std::string result = Strings::toUpper(input);

    EXPECT_EQ("HELLO, WORLD 123!", result);
}

TEST(Given_Strings, When_ToLowerWithWideString_ReturnsAllLowerCaseWide)
{
    std::wstring input = L"SHA256";

    std::wstring result = Strings::toLower(input);

    EXPECT_EQ(L"sha256", result);
}

TEST(Given_Strings, When_EqualsCaseInsensitiveMatching_ReturnsTrue)
{
    std::string a = "SHA256";
    std::string b = "sha256";

    bool match = Strings::equalsCaseInsensitive(a, b);

    EXPECT_TRUE(match);
}

TEST(Given_Strings, When_EqualsCaseInsensitiveDifferentLength_ReturnsFalse)
{
    std::string a = "SHA256";
    std::string b = "sha2567";

    bool match = Strings::equalsCaseInsensitive(a, b);

    EXPECT_FALSE(match);
}

TEST(Given_Strings, When_EqualsCaseInsensitiveDifferentCharacters_ReturnsFalse)
{
    std::string a = "SHA256";
    std::string b = "SHA384";

    bool match = Strings::equalsCaseInsensitive(a, b);

    EXPECT_FALSE(match);
}
