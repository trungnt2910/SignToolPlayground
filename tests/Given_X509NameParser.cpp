#include <gtest/gtest.h>

#include "crypto/CckyException.h"
#ifndef _WIN32
#include "crypto/openssl/X509NameParser.h"
#endif

namespace ccky
{
namespace crypto
{

TEST(Given_X509NameParser, When_EmptyInput_ReturnsEmpty)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("");

    EXPECT_TRUE(result.empty());
#endif
}

TEST(Given_X509NameParser, When_SimpleCn_ParsesCorrectly)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky");

    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].size(), 1);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky");
#endif
}

TEST(Given_X509NameParser, When_MultipleRdns_ParsesCorrectly)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky, O=ccky, C=AU");

    ASSERT_EQ(result.size(), 3);
    ASSERT_EQ(result[0].size(), 1);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky");
    ASSERT_EQ(result[1].size(), 1);
    EXPECT_EQ(result[1][0].key, "O");
    EXPECT_EQ(result[1][0].value, "ccky");
    ASSERT_EQ(result[2].size(), 1);
    EXPECT_EQ(result[2][0].key, "C");
    EXPECT_EQ(result[2][0].value, "AU");
#endif
}

TEST(Given_X509NameParser, When_MultiValuedRdn_ParsesCorrectly)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky+O=ccky");

    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].size(), 2);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky");
    EXPECT_EQ(result[0][1].key, "O");
    EXPECT_EQ(result[0][1].value, "ccky");
#endif
}

TEST(Given_X509NameParser, When_MixedRdns_ParsesCorrectly)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky+O=ccky, C=AU");

    ASSERT_EQ(result.size(), 2);
    ASSERT_EQ(result[0].size(), 2);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky");
    EXPECT_EQ(result[0][1].key, "O");
    EXPECT_EQ(result[0][1].value, "ccky");
    ASSERT_EQ(result[1].size(), 1);
    EXPECT_EQ(result[1][0].key, "C");
    EXPECT_EQ(result[1][0].value, "AU");
#endif
}

TEST(Given_X509NameParser, When_SpacesInInput_TrimsThem)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("  CN  =  ccky  ,  O  =  ccky  ");

    ASSERT_EQ(result.size(), 2);
    ASSERT_EQ(result[0].size(), 1);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky");
    ASSERT_EQ(result[1].size(), 1);
    EXPECT_EQ(result[1][0].key, "O");
    EXPECT_EQ(result[1][0].value, "ccky");
#endif
}

TEST(Given_X509NameParser, When_EscapedSeparators_PreservesThem)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky\\, junior, O=ccky\\+co, C=AU");

    ASSERT_EQ(result.size(), 3);
    ASSERT_EQ(result[0].size(), 1);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky, junior");
    ASSERT_EQ(result[1].size(), 1);
    EXPECT_EQ(result[1][0].key, "O");
    EXPECT_EQ(result[1][0].value, "ccky+co");
    ASSERT_EQ(result[2].size(), 1);
    EXPECT_EQ(result[2][0].key, "C");
    EXPECT_EQ(result[2][0].value, "AU");
#endif
}

TEST(Given_X509NameParser, When_EscapedSpaces_PreservesThem)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    auto result = X509NameParser::parse("CN=ccky\\ , O=\\ ccky");

    ASSERT_EQ(result.size(), 2);
    ASSERT_EQ(result[0].size(), 1);
    EXPECT_EQ(result[0][0].key, "CN");
    EXPECT_EQ(result[0][0].value, "ccky ");
    ASSERT_EQ(result[1].size(), 1);
    EXPECT_EQ(result[1][0].key, "O");
    EXPECT_EQ(result[1][0].value, " ccky");
#endif
}

TEST(Given_X509NameParser, When_InvalidInputs_ThrowsException)
{
#ifdef _WIN32
    GTEST_SKIP() << "X509NameParser is only built with OpenSSL backend.";
#else
    EXPECT_THROW(X509NameParser::parse("CN"), CckyException);
    EXPECT_THROW(X509NameParser::parse("CN="), CckyException);
    EXPECT_THROW(X509NameParser::parse("=ccky"), CckyException);
    EXPECT_THROW(X509NameParser::parse("CN=ccky,"), CckyException);
    EXPECT_THROW(X509NameParser::parse("CN=ccky+"), CckyException);
    EXPECT_THROW(X509NameParser::parse("CN=ccky\\"), CckyException);
#endif
}

} // namespace crypto
} // namespace ccky
