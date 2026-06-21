#include <memory>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"

class Given_CliParser : public CckyTest
{
};

TEST_F(Given_CliParser, When_CertMgrAddCommand_ParsedCorrectly)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/all",
        "/c",
        "myFile.ext",
        "newFile.ext",
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    EXPECT_EQ(args.command, "certmgr");
    EXPECT_EQ(args.subcommand, "/add");
    EXPECT_TRUE(args.hasFlag("all"));
    EXPECT_TRUE(args.hasFlag("c"));
    EXPECT_EQ(args.positional.size(), 2);
    if (args.positional.size() == 2)
    {
        EXPECT_EQ(args.positional[0], "myFile.ext");
        EXPECT_EQ(args.positional[1], "newFile.ext");
    }
}

TEST_F(Given_CliParser, When_SignToolSignCommand_ParsedCorrectly)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        "MyCert.pfx",
        "/p",
        "MyPassword",
        "/fd",
        "SHA256",
        "MyFile.exe",
    };
    auto args = ccky::cli::CliParser::parse(10, const_cast<char**>(argv), registry);

    EXPECT_EQ(args.command, "signtool");
    EXPECT_EQ(args.subcommand, "sign");
    EXPECT_EQ(args.getFlagValue("f"), "MyCert.pfx");
    EXPECT_EQ(args.getFlagValue("p"), "MyPassword");
    EXPECT_EQ(args.getFlagValue("fd"), "SHA256");
    EXPECT_EQ(args.positional.size(), 1);
    if (args.positional.size() == 1)
    {
        EXPECT_EQ(args.positional[0], "MyFile.exe");
    }
}

TEST_F(Given_CliParser, When_CaseInsensitiveFlags_MatchedCorrectly)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/CRL",
        "/sha1",
        "123456",
        "store.cer",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    EXPECT_TRUE(args.hasFlag("crl"));
    EXPECT_EQ(args.getFlagValue("SHA1"), "123456");
}

TEST_F(Given_CliParser, When_AbsoluteUnixPath_ParsedAsPositional)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        "/absolute/path/to/cert.pfx",
        "/absolute/path/to/app.exe",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    EXPECT_EQ(args.command, "signtool");
    EXPECT_EQ(args.subcommand, "sign");
    EXPECT_EQ(args.getFlagValue("f"), "/absolute/path/to/cert.pfx");
    ASSERT_EQ(args.positional.size(), 1);
    EXPECT_EQ(args.positional[0], "/absolute/path/to/app.exe");
}
