#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"

class Given_CckyHelp : public CckyTest
{
  protected:
    void SetUp() override
    {
        CckyTest::SetUp();
        registry.registerCommand(
            std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err));
        registry.registerCommand(
            std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err));
    }

    std::stringstream out;
    std::stringstream err;
};

TEST_F(Given_CckyHelp, When_CertMgrHelp_MatchesStderr)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);
    auto cmd = registry.getCommand("certmgr");
    ASSERT_NE(cmd, nullptr);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_help_stderr.txt"));

    int result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CckyHelp, When_SignToolHelp_MatchesStderr)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);
    auto cmd = registry.getCommand("signtool");
    ASSERT_NE(cmd, nullptr);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/signtool_help_stderr.txt"));

    int result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CckyHelp, When_SignToolSignHelp_MatchesStderr)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);
    auto cmd = registry.getCommand("signtool");
    ASSERT_NE(cmd, nullptr);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_help_stderr.txt"));

    int result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(err.str(), expected);
}
