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
  protected:
    bool hasSystemCertificate(const std::string& storeName, const std::string& commonName)
    {
        auto store =
            ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, storeName);
        store->load(storeName);
        for (const auto& c : store->getCertificates())
        {
            if (c->getCommonName() == commonName)
            {
                return true;
            }
        }
        return false;
    }
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

    int result = -1;
    if (cmd)
    {
        result = cmd->execute(args);
    }

    EXPECT_NE(cmd, nullptr);
    EXPECT_EQ(result, 0);
}

TEST_F(Given_CertMgr, When_SystemStoreRequested_ReturnsError)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }

    const char* argv[] = {
        "ccky",
        "certmgr",
        "/v",
        "/s",
        "my",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    auto cmd = registry.getCommand("certmgr");

    int result = -1;
    if (cmd)
    {
        result = cmd->execute(args);
    }

    EXPECT_NE(cmd, nullptr);
    EXPECT_EQ(result, 0);
}

TEST_F(Given_CertMgr, When_CertMgrPut_MatchesCertificate)
{
    std::string pePath = getTestDataPath("tests/data/lxmonika.sys");
    std::string expectedCerPath = getTestDataPath("tests/data/lxmonika.cer");
    std::string actualCerPath = "extracted_test.cer";
    registerTemporaryFile(actualCerPath);
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
    ASSERT_NE(cmd, nullptr);

    int result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    expectFilesEqual(expectedCerPath, actualCerPath);
}

TEST_F(Given_CertMgr, When_CertMgrAdd_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    registerSystemStoreCert("my", "ccky");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
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
    ASSERT_NE(cmd, nullptr);

    int result = cmd->execute(addArgs);

    EXPECT_EQ(result, 0);
    EXPECT_TRUE(hasSystemCertificate("my", "ccky"));
}

TEST_F(Given_CertMgr, When_CertMgrDel_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    registerSystemStoreCert("my", "ccky");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
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
    ASSERT_NE(cmd, nullptr);
    cmd->execute(addArgs);
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

    int result = cmd->execute(delArgs);

    EXPECT_EQ(result, 0);
    EXPECT_FALSE(hasSystemCertificate("my", "ccky"));
}

TEST_F(Given_CertMgr, When_CertMgrDelByHash_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    registerSystemStoreCert("my", "ccky");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
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
    ASSERT_NE(cmd, nullptr);
    cmd->execute(addArgs);
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, "my");
    ASSERT_NO_THROW(store->load("my"));
    std::string targetSha1;
    for (const auto& c : store->getCertificates())
    {
        if (c->getCommonName() == "ccky")
        {
            targetSha1 = c->getSha1();
            break;
        }
    }
    ASSERT_FALSE(targetSha1.empty());
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

    int result = cmd->execute(delArgs);

    EXPECT_EQ(result, 0);
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
    cmd->setRegistry(&registry);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/add",
        "/c",
        "source.cer",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_add_missingdestinationfilename_stderr.txt"));

    int result = cmd->execute(args);

    EXPECT_EQ(result, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrDisplayMissingSource_MatchesStderr)
{
    std::stringstream out;
    std::stringstream err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "certmgr",
    };
    auto args = ccky::cli::CliParser::parse(2, const_cast<char**>(argv), registry);
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_display_missingsourcefilename_stderr.txt"));

    int result = cmd->execute(args);

    EXPECT_EQ(result, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrAddBadSource_MatchesStderr)
{
    std::stringstream out;
    std::stringstream err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
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
    std::string expected = getTestTextContent(
        getTestDataPath("tests/data/output/certmgr_add_badsourcestore_stderr.txt"));

    auto result = cmd->execute(args);

    EXPECT_EQ(result, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrDisplay_MatchesStdout)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "certmgr",
        "/c",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_display_stdout.txt"));

    auto result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(err.str(), "");
    EXPECT_EQ(out.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrAdd_MatchesStdout)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string destPath = "temp_dest.cer";
    registerTemporaryFile(destPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
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
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_stdout.txt"));

    auto result = cmd->execute(args);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(out.str(), expected);
}

TEST_F(Given_CertMgr, When_CertMgrDelBadSha1_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
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

    int result = cmd->execute(args);

    EXPECT_EQ(result, 1);
    EXPECT_EQ(err.str(),
        getTestTextContent(getTestDataPath("tests/data/output/certmgr_del_badsha1_stderr.txt")));
    EXPECT_EQ(out.str(), "");
}

TEST_F(Given_CertMgr, When_CertMgrDelNoMatchingSha1_MatchesOutput)
{
    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::CertMgrCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
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

    int result = cmd->execute(args);

    EXPECT_EQ(result, 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/certmgr_del_nomatchingsha1_stderr.txt")));
    EXPECT_EQ(out.str(), "");
}
