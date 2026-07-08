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

TEST(Given_Strings, When_HexWithVectorBytes_ReturnsUppercaseHexString)
{
    std::vector<uint8_t> bytes = {0x00, 0x1A, 0x2B, 0xFF, 0x09};

    std::string result = Strings::hex(bytes);

    EXPECT_EQ("001A2BFF09", result);
}

TEST(Given_Strings, When_HexWithWCharTemplate_ReturnsUppercaseHexWString)
{
    std::vector<uint8_t> bytes = {0x00, 0x1A, 0x2B, 0xFF, 0x09};

    std::wstring result = Strings::hex<wchar_t>(bytes);

    EXPECT_EQ(L"001A2BFF09", result);
}

TEST(Given_Strings, When_HexWithEmptyBytes_ReturnsEmptyString)
{
    std::vector<uint8_t> bytes = {};

    std::string result = Strings::hex(bytes);

    EXPECT_TRUE(result.empty());
}

TEST(Given_Strings, When_HexWithGroupSize_GroupsOutputWithSeparators)
{
    std::vector<uint8_t> bytes = {0x00, 0x1A, 0x2B, 0xFF, 0x09};

    std::string result = Strings::hex(bytes, 1, ' ');

    EXPECT_EQ("00 1A 2B FF 09", result);
}

TEST(Given_Strings, When_HexWithCustomGroupAndSeparator_GroupsCorrectly)
{
    std::vector<uint8_t> bytes = {0x00, 0x1A, 0x2B, 0xFF, 0x09, 0x11, 0x22};

    std::string result = Strings::hex(bytes, 4, '-');

    EXPECT_EQ("001A2BFF-091122", result);
}

TEST(Given_Strings, When_HexWithGroupSizeLargerThanBytes_DoesNotAddSeparators)
{
    std::vector<uint8_t> bytes = {0x00, 0x1A, 0x2B};

    std::string result = Strings::hex(bytes, 5, '-');

    EXPECT_EQ("001A2B", result);
}
