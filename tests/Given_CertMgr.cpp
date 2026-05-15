#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"
#include "crypto/AuthenticodeSigner.h"
#include "crypto/CryptoFactory.h"

class Given_CertMgr : public CckyTest
{
};

TEST_F(Given_CertMgr, When_HelpRequested_ReturnsZero)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("certmgr");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(args), 0);
    }
}

TEST_F(Given_CertMgr, When_SystemStoreRequested_ReturnsError)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/v",
        "/s",
        "my",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("certmgr");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        if (ccky::crypto::CryptoFactory::getBackendType() == "windows")
        {
            EXPECT_EQ(cmd->execute(args), 0);
        }
        else
        {
            EXPECT_EQ(cmd->execute(args), 1);
        }
    }
}

TEST_F(Given_CertMgr, When_CertMgrPut_MatchesCertificate)
{
    std::string pePath = getTestDataPath("tests/data/lxmonika.sys");
    std::string expectedCerPath = getTestDataPath("tests/data/lxmonika.cer");
    std::string actualCerPath = "extracted_test.cer";

    const char* argv[] = {
        "ccky",
        "certmgr",
        "/put",
        "/c",
        pePath.c_str(),
        actualCerPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("certmgr");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(args), 0);

        std::ifstream expectedFile(expectedCerPath, std::ios::binary);
        std::ifstream actualFile(actualCerPath, std::ios::binary);

        EXPECT_TRUE(expectedFile.is_open());
        EXPECT_TRUE(actualFile.is_open());

        if (expectedFile.is_open() && actualFile.is_open())
        {
            std::vector<uint8_t> expectedBytes(
                (std::istreambuf_iterator<char>(expectedFile)), std::istreambuf_iterator<char>());
            std::vector<uint8_t> actualBytes(
                (std::istreambuf_iterator<char>(actualFile)), std::istreambuf_iterator<char>());

            EXPECT_EQ(expectedBytes, actualBytes);
        }
    }
    std::filesystem::remove(actualCerPath);
}

TEST_F(Given_CertMgr, When_CertMgrAddAndDelete_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");

    // 1. certmgr /add /c tests/data/ccky.pfx /s my
    const char* addArgv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        pfxPath.c_str(),
        "/s",
        "my",
    };
    auto addArgs = ccky::cli::CliParser::parse(7, const_cast<char**>(addArgv), registry);
    auto cmd = registry.getCommand("certmgr");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(addArgs), 0);
    }

    // Check existence
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, "my");
    EXPECT_NO_THROW(store->load("my"));
    bool found = false;
    for (const auto& c : store->getCertificates())
    {
        if (c->getCommonName() == "ccky")
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);

    // 2. certmgr /del /c /n ccky /s my
    const char* delArgv[] = {
        "ccky",
        "certmgr",
        "/del",
        "/c",
        "/n",
        "ccky",
        "/s",
        "my",
    };
    auto delArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(delArgv), registry);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(delArgs), 0);
    }
}

TEST_F(Given_CertMgr, When_CertMgrAddAndDeleteByHash_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");

    // 1. certmgr /add /c tests/data/ccky.pfx /s my
    const char* addArgv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        pfxPath.c_str(),
        "/s",
        "my",
    };
    auto addArgs = ccky::cli::CliParser::parse(7, const_cast<char**>(addArgv), registry);
    auto cmd = registry.getCommand("certmgr");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(addArgs), 0);
    }

    // 2. Get SHA1 hash dynamically
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, "my");
    EXPECT_NO_THROW(store->load("my"));
    std::string targetSha1;
    for (const auto& c : store->getCertificates())
    {
        if (c->getCommonName() == "ccky")
        {
            targetSha1 = c->getSha1();
            break;
        }
    }
    EXPECT_FALSE(targetSha1.empty());

    if (!targetSha1.empty() && cmd)
    {
        // 3. certmgr /del /c /sha1 <hash> /s my
        const char* delArgv[] = {
            "ccky",
            "certmgr",
            "/del",
            "/c",
            "/sha1",
            targetSha1.c_str(),
            "/s",
            "my",
        };
        auto delArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(delArgv), registry);
        EXPECT_EQ(cmd->execute(delArgs), 0);
    }
}

TEST_F(Given_CertMgr, When_CertMgrSourceSystemAndDestFile_ParsedCorrectly)
{
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        "/s",
        "my",
        "dest.cer",
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    EXPECT_EQ(args.positional.size(), 2);
    EXPECT_EQ(args.positionalFlags.size(), 2);
    EXPECT_TRUE(args.positionalFlags[0].find("s") != args.positionalFlags[0].end());
    EXPECT_TRUE(args.positionalFlags[1].find("s") == args.positionalFlags[1].end());
}

TEST_F(Given_CertMgr, When_CertMgrAddMissingDest_MatchesStderr)
{
    std::stringstream out;
    std::stringstream err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        "source.cer",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_add_missingdestinationfilename_stderr.txt"));
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrDisplayMissingSource_MatchesStderr)
{
    std::stringstream out;
    std::stringstream err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
    };
    auto args = ccky::cli::CliParser::parse(2, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_display_missingsourcefilename_stderr.txt"));
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrAddBadSource_MatchesStderr)
{
    std::stringstream out;
    std::stringstream err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        "nonexistent_bad_file.cer",
        "dest.cer",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_add_badsourcestore_stderr.txt"));
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrDisplay_MatchesStdout)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/c",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 0);
    EXPECT_EQ(err.str(), "");

    EXPECT_EQ(out.str(),
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_display_stdout.txt")));
}

TEST_F(Given_CertMgr, When_CertMgrAdd_MatchesStdout)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string destPath = "temp_dest.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        pfxPath.c_str(),
        destPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 0);
    EXPECT_EQ(
        out.str(), getTestTextContent(getTestDataPath("tests/data/output/certmgr_stdout.txt")));
    std::filesystem::remove(destPath);
}

TEST_F(Given_CertMgr, When_CertMgrDelBadSha1_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/del",
        "/c",
        "/sha1",
        "badsha1",
        "source.cer",
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(),
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_del_badsha1_stderr.txt")));
    EXPECT_EQ(out.str(), "");
}

TEST_F(Given_CertMgr, When_CertMgrDelNoMatchingSha1_MatchesOutput)
{
    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/del",
        "/c",
        "/sha1",
        "0123456789012345678901234567890123456789",
        cerPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/certmgr_del_nomatchingsha1_stderr.txt")));
    EXPECT_EQ(out.str(), "");
}
