#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"
#include "commands/Pvk2PfxCommand.h"
#include "crypto/CryptoFactory.h"
#include "crypto/ICertStore.h"

class Given_Pvk2Pfx : public CckyTest
{
  protected:
    std::string tempDir;

    void SetUp() override { CckyTest::SetUp(); }

    void TearDown() override
    {
        if (!tempDir.empty())
        {
            std::filesystem::remove_all(tempDir);
        }
        CckyTest::TearDown();
    }

    std::string getTempDir()
    {
        if (tempDir.empty())
        {
            tempDir = "temp_pvk2pfx_test";
            std::filesystem::create_directories(tempDir);
        }
        return tempDir;
    }
};

TEST_F(Given_Pvk2Pfx, When_Help_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_help_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_MissingArgs_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
    };
    auto args = ccky::cli::CliParser::parse(2, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_help_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_BadFile_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pvkPath = getTestDataPath("tests/data/nonexistent.pvk");
    std::string spcPath = getTestDataPath("tests/data/nonexistent.spc");
    std::string pfxPath = getTempDir() + "/out.pfx";
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_filenotfound_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_BadPassword_MatchesStderr)
{
    std::string pvkPath = getTempDir() + "/temp_encrypted.pvk";
    std::string spcPath = getTempDir() + "/temp_encrypted.cer";
    {
        std::stringstream mcOut, mcErr;
        std::stringstream mcIn("realpassword\nrealpassword\nrealpassword\n");
        auto mcCmd = std::make_shared<ccky::commands::MakeCertCommand>(mcIn, mcOut, mcErr);
        mcCmd->setRegistry(&registry);
        const char* mcArgv[] = {"ccky", "makecert", "-sv", pvkPath.c_str(), spcPath.c_str()};
        auto mcArgs = ccky::cli::CliParser::parse(5, const_cast<char**>(mcArgv), registry);
        // Provide "realpassword\nrealpassword\nrealpassword\n" for PVK creation (Create, Confirm &
        // Reload)
        ASSERT_EQ(mcCmd->execute(mcArgs), 0);
    }
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pfxPath = getTempDir() + "/out.pfx";
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
        "-pi",
        "wrongpassword",
    };
    auto args = ccky::cli::CliParser::parse(10, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_badpassword_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_Pvk2PfxSucceeds_CreatesPfx)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pvkPath = getTestDataPath("tests/data/ccky.pvk");
    std::string spcPath = getTestDataPath("tests/data/ccky.cer");
    std::string pfxPath = getTempDir() + "/out.pfx";
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
        "-po",
        "newpassword",
    };
    auto args = ccky::cli::CliParser::parse(10, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PfxFile, pfxPath);
    ccky::crypto::StoreOptions options;
    options.password = "newpassword";
    store->load(pfxPath, options);
    auto certs = store->getCertificates();

    EXPECT_EQ(err.str(), "");
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(out.str(), getTestTextContent("tests/data/output/pvk2pfx_stdout.txt"));
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSubjectDN(), "CN=ccky");
}

TEST_F(Given_Pvk2Pfx, When_OutputFileExists_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pvkPath = getTestDataPath("tests/data/ccky.pvk");
    std::string spcPath = getTestDataPath("tests/data/ccky.cer");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx"); // File exists
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(
        err.str(), getTestTextContent("tests/data/output/pvk2pfx_outputfileexists_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_PvkInvalidFormat_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pvkPath = getTestDataPath("tests/data/ccky.cer"); // Pass cer as pvk
    std::string spcPath = getTestDataPath("tests/data/ccky.cer");
    std::string pfxPath = getTempDir() + "/out.pfx";
    const char* argv[] = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_badfile_stderr.txt"));
}
