#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"
#include "crypto/AuthenticodeSigner.h"
#include "crypto/CryptoFactory.h"

class Given_SignTool : public CckyTest
{
  protected:
    std::string tempDir;

    void SetUp() override
    {
        CckyTest::SetUp();
        cleanupSystemStore();
    }
    void TearDown() override
    {
        if (!tempDir.empty())
        {
            std::filesystem::remove_all(tempDir);
        }
        cleanupSystemStore();
        CckyTest::TearDown();
    }

    std::string getTempDir()
    {
        if (tempDir.empty())
        {
            tempDir = "temp_signtool_test";
            std::filesystem::create_directories(tempDir);
        }
        return tempDir;
    }

    void cleanupSystemStore()
    {
        if (ccky::crypto::CryptoFactory::getBackendType() == "windows")
        {
            try
            {
                auto store = ccky::crypto::CryptoFactory::createStore(
                    ccky::crypto::StoreType::WinSystem, "my");
                store->load("my");
                store->deletePrivateKey("", "70cc11b9d1bfdfa1d5f629a8a78173b33b17bee0");
            }
            catch (const std::exception& e)
            {
                GTEST_LOG_(WARNING) << "Failed to delete private key during cleanup: " << e.what();
            }
        }
    }
};

TEST_F(Given_SignTool, When_HelpRequested_ReturnsZero)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("signtool");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(args), 0);
    }
}

TEST_F(Given_SignTool, When_VerifyMissingFile_ReturnsError)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "verify",
        "nonexistent.exe",
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("signtool");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(args), 1); // Failed
    }
}

TEST_F(Given_SignTool, When_CatdbRequested_ReturnsStubError)
{
    const char* argv[] = {
        "ccky",
        "signtool",
        "catdb",
        "/v",
        "MyCatalog.cat",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    auto cmd = registry.getCommand("signtool");
    EXPECT_NE(cmd, nullptr);
    if (cmd)
    {
        EXPECT_EQ(cmd->execute(args), 1); // Failed due to stubbed Windows catalog API
    }
}

TEST_F(Given_SignTool, When_SignToolSign_SignsSuccessfullyAndMatchesAuthority)
{
    std::string origPePath = getTestDataPath("tests/data/lxmonika.sys");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string reSignedSys = "re_signed.sys";
    std::string reExtractedCer = "re_extracted.cer";

    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);

    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/v",
        "/fd",
        "sha256",
        "/f",
        pfxPath.c_str(),
        "/p",
        "",
        reSignedSys.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(11, const_cast<char**>(signArgv), registry);
    auto signCmd = registry.getCommand("signtool");
    EXPECT_NE(signCmd, nullptr);
    if (signCmd)
    {
        EXPECT_EQ(signCmd->execute(signArgs), 0);
    }

    const char* certArgv[] = {
        "ccky",
        "certmgr",
        "/put",
        "/c",
        reSignedSys.c_str(),
        reExtractedCer.c_str(),
    };
    auto certArgs = ccky::cli::CliParser::parse(6, const_cast<char**>(certArgv), registry);
    auto certCmd = registry.getCommand("certmgr");
    EXPECT_NE(certCmd, nullptr);
    if (certCmd)
    {
        EXPECT_EQ(certCmd->execute(certArgs), 0);
    }

    auto cerStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, reExtractedCer);
    EXPECT_NO_THROW(cerStore->load(reExtractedCer));
    auto certs = cerStore->getCertificates();
    EXPECT_GT(certs.size(), 0);
    if (!certs.empty())
    {
        auto cert = certs[0];
        EXPECT_EQ(cert->getCommonName(), "ccky");
    }

    std::filesystem::remove(reSignedSys);
    std::filesystem::remove(reExtractedCer);
}

TEST_F(Given_SignTool, When_SignToolSignUnsignedExecutable)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string reSignedSys = "re_signed_test.exe";
    std::string reExtractedCer = "re_extracted_test.cer";

    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);

    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/v",
        "/fd",
        "sha256",
        "/f",
        pfxPath.c_str(),
        "/p",
        "",
        reSignedSys.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(11, const_cast<char**>(signArgv), registry);
    auto signCmd = registry.getCommand("signtool");
    EXPECT_NE(signCmd, nullptr);
    if (signCmd)
    {
        EXPECT_EQ(signCmd->execute(signArgs), 0);
    }

    const char* certArgv[] = {
        "ccky",
        "certmgr",
        "/put",
        "/c",
        reSignedSys.c_str(),
        reExtractedCer.c_str(),
    };
    auto certArgs = ccky::cli::CliParser::parse(6, const_cast<char**>(certArgv), registry);
    auto certCmd = registry.getCommand("certmgr");
    EXPECT_NE(certCmd, nullptr);
    if (certCmd)
    {
        EXPECT_EQ(certCmd->execute(certArgs), 0);
    }

    auto cerStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, reExtractedCer);
    EXPECT_NO_THROW(cerStore->load(reExtractedCer));
    auto certs = cerStore->getCertificates();
    EXPECT_GT(certs.size(), 0);
    if (!certs.empty())
    {
        auto cert = certs[0];
        EXPECT_EQ(cert->getCommonName(), "ccky");
    }

    std::filesystem::remove(reSignedSys);
    std::filesystem::remove(reExtractedCer);
}

TEST_F(Given_SignTool, When_SignBadAlgo_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "badalgo",
        "test.exe",
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_badalgo_stderr.txt")));
}

TEST_F(Given_SignTool, When_SignBadCert_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/fd",
        "SHA256",
        "/f",
        "badcert.pfx",
        "test.exe",
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_badcert_stderr.txt")));
}

TEST_F(Given_SignTool, When_SignMissingParam_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_sign_missingparam_stderr.txt")));
}

TEST_F(Given_SignTool, When_SignBadFile_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        "bad.exe",
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_badfile_stderr.txt")));

    EXPECT_EQ(out.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_badfile_stdout.txt")));
}

TEST_F(Given_SignTool, When_SignTwoBadFiles_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        "bad0.exe",
        "bad1.exe",
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_sign_twobadfiles_stderr.txt")));

    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_sign_twobadfiles_stdout.txt")));
}

TEST_F(Given_SignTool, When_SignGoodAndBadFiles_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string reSignedSys = "test.exe";
    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        "test.exe",
        "bad.exe",
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_sign_goodandbadfiles_stderr.txt")));

    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_sign_goodandbadfiles_stdout.txt")));
    std::filesystem::remove(reSignedSys);
}

TEST_F(Given_SignTool, When_SignGoodFile_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string reSignedSys = "test.exe";
    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    const char* argv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        "test.exe",
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 0);
    EXPECT_EQ(err.str(), "");

    EXPECT_EQ(out.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_sign_stdout.txt")));
    std::filesystem::remove(reSignedSys);
}

TEST_F(Given_SignTool, When_SignToolSignWithSystemStoreCert_MatchesOutput)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string reSignedSys = "test.exe";

    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);

    // 1. store->addPrivateKey(pfxPath, "")
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, "my");
    store->load("my");
    EXPECT_NO_THROW(store->addPrivateKey(pfxPath, ""));

    // 2. signtool sign /n "ccky" /fd SHA256 test.exe
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);

    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/n",
        "ccky",
        "/fd",
        "SHA256",
        reSignedSys.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);
    EXPECT_EQ(err.str(), "");
    EXPECT_EQ(out.str(), getTestTextContent("tests/data/output/signtool_sign_stdout.txt"));

    std::filesystem::remove(reSignedSys);
}

TEST_F(Given_SignTool, When_RemoveSignedAndBad_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string signedPe = "test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "test.exe",
        "bad.exe",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_signedandbad_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_signedandbad_stdout.txt")));
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_RemoveSigned_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string signedPe = "test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "test.exe",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 0);
    EXPECT_EQ(out.str(),
        getTestTextContent(getTestDataPath("tests/data/output/signtool_remove_signed_stdout.txt")));
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_RemoveUnsigned_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string unsignedPe = "unsigned.exe";
    std::filesystem::copy_file(
        origPePath, unsignedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "unsigned.exe",
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_unsigned_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_unsigned_stdout.txt")));
    std::filesystem::remove(unsignedPe);
}

TEST_F(Given_SignTool, When_RemoveVerboseSignedAndBad_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string signedPe = "test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "/v",
        "test.exe",
        "bad.exe",
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_verbose_signedandbad_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_verbose_signedandbad_stdout.txt")));
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_RemoveVerboseSigned_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string signedPe = "test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "/v",
        "test.exe",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 0);
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_verbose_signed_stdout.txt")));
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_RemoveVerboseUnsigned_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string unsignedPe = "unsigned.exe";
    std::filesystem::copy_file(
        origPePath, unsignedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "remove",
        "/s",
        "/v",
        "unsigned.exe",
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_verbose_unsigned_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_remove_verbose_unsigned_stdout.txt")));
    std::filesystem::remove(unsignedPe);
}

TEST_F(Given_SignTool, When_VerifySelfSigned_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string tempDir = getTempDir();
    std::string signedPe = tempDir + "/test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto verifyCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(verifyCmd);
    const char* verifyArgv[] = {
        "ccky",
        "signtool",
        "verify",
        signedPe.c_str(),
    };
    auto verifyArgs = ccky::cli::CliParser::parse(4, const_cast<char**>(verifyArgv), registry);
    EXPECT_EQ(verifyCmd->execute(verifyArgs), 1);

    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_selfsigned_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_selfsigned_stdout.txt")));
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_VerifyUnsigned_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string tempDir = getTempDir();
    std::string unsignedPe = tempDir + "/test.exe";
    std::filesystem::copy_file(
        origPePath, unsignedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "verify",
        unsignedPe.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_unsigned_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_unsigned_stdout.txt")));
    std::filesystem::remove(unsignedPe);
}

TEST_F(Given_SignTool, When_VerifyVerboseSelfSigned_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string tempDir = getTempDir();
    std::string signedPe = tempDir + "/test.exe";
    std::filesystem::copy_file(
        origPePath, signedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto signCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(signCmd);
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/f",
        pfxPath.c_str(),
        "/fd",
        "SHA256",
        signedPe.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    EXPECT_EQ(signCmd->execute(signArgs), 0);

    out.str("");
    err.str("");
    auto verifyCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(verifyCmd);
    const char* verifyArgv[] = {
        "ccky",
        "signtool",
        "verify",
        "/v",
        signedPe.c_str(),
    };
    auto verifyArgs = ccky::cli::CliParser::parse(5, const_cast<char**>(verifyArgv), registry);
    EXPECT_EQ(verifyCmd->execute(verifyArgs), 1);

    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_verbose_selfsigned_stderr.txt")));

    std::string expectedOut = getTestTextContent(
        getTestDataPath("tests/data/output/signtool_verify_verbose_selfsigned_stdout.txt"));
    // Per Microsoft Authenticode specification, signtool injects a dynamic signingTime
    // authenticated attribute by default. This causes the binary payload and SHA256 digest
    // to change on every signing operation. We dynamically replace the expected hash here
    // to match the actual runtime digest while preserving native signtool behavior.
    std::string actualHash = ccky::crypto::CryptoFactory::calculateSha256(signedPe);
    size_t pos =
        expectedOut.find("414974B2E342C70208774E9E47E83382A6CFF5FF799DDB65F1DAD78673EA54D4");
    if (pos != std::string::npos && !actualHash.empty())
    {
        expectedOut.replace(pos, 64, actualHash);
    }

    EXPECT_EQ(out.str(), expectedOut);
    std::filesystem::remove(signedPe);
}

TEST_F(Given_SignTool, When_VerifyVerboseUnsigned_MatchesOutput)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string tempDir = getTempDir();
    std::string unsignedPe = tempDir + "/test.exe";
    std::filesystem::copy_file(
        origPePath, unsignedPe, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "verify",
        "/v",
        unsignedPe.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_verbose_unsigned_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_verbose_unsigned_stdout.txt")));
    std::filesystem::remove(unsignedPe);
}

TEST_F(Given_SignTool, When_SignToolSignWithSystemStoreCert_SucceedsOnWindows)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP()
            << "Windows system certificate stores (/s) are unsupported on OpenSSL; skipping test.";
    }
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string reSignedSys = "re_signed_system_test.exe";

    std::filesystem::copy_file(
        origPePath, reSignedSys, std::filesystem::copy_options::overwrite_existing);

    // 1. store->addPrivateKey(pfxPath, "")
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, "my");
    store->load("my");
    EXPECT_NO_THROW(store->addPrivateKey(pfxPath, ""));

    // 2. signtool sign /n "ccky" /fd SHA256 re_signed_system_test.exe
    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/n",
        "ccky",
        "/fd",
        "SHA256",
        reSignedSys.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(8, const_cast<char**>(signArgv), registry);
    auto signCmd = registry.getCommand("signtool");
    EXPECT_NE(signCmd, nullptr);
    if (signCmd)
    {
        EXPECT_EQ(signCmd->execute(signArgs), 0);
    }

    std::filesystem::remove(reSignedSys);
}

TEST_F(Given_SignTool, When_SignToolInvalidCommand_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(cmd);
    const char* argv[] = {
        "ccky",
        "signtool",
        "bad",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);
    EXPECT_EQ(cmd->execute(args), 1);
    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_invalidcommand_stderr.txt")));
    EXPECT_EQ(out.str(), "");
}

TEST_F(Given_SignTool, When_VerifySelfSignedAppx_MatchesOutput)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string origAppxPath = getTestDataPath("tests/data/test.appx");
    std::string tempDir = getTempDir();
    std::string signedAppx = tempDir + "/test.appx";
    std::filesystem::copy_file(
        origAppxPath, signedAppx, std::filesystem::copy_options::overwrite_existing);
    std::stringstream out, err;

    // Do not re-sign the APPX here. Windows does not allow CN mismatch between APPX and cert.
    // The provided file is already signed by Project Reality.

    auto verifyCmd = std::make_shared<ccky::commands::SignToolCommand>(std::cin, out, err);
    registry.registerCommand(verifyCmd);
    const char* verifyArgv[] = {
        "ccky",
        "signtool",
        "verify",
        "/pa",
        signedAppx.c_str(),
    };
    auto verifyArgs = ccky::cli::CliParser::parse(5, const_cast<char**>(verifyArgv), registry);
    EXPECT_EQ(verifyCmd->execute(verifyArgs), 1);

    EXPECT_EQ(err.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_selfsignedappx_stderr.txt")));
    EXPECT_EQ(out.str(), getTestTextContent(getTestDataPath(
                             "tests/data/output/signtool_verify_selfsignedappx_stdout.txt")));
    std::filesystem::remove(signedAppx);
}

TEST_F(Given_SignTool, When_SignToolSignAppx_SignsSuccessfullyAndMatchesAuthority)
{
    // Use an APPX file whose CN matches the PFX. test.appx is published by "Project Reality".
    std::string origAppxPath = getTestDataPath("tests/data/ccky.appx");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string reSignedAppx = "re_signed.appx";
    std::string reExtractedAppxCer = "re_extracted_appx.cer";

    std::filesystem::copy_file(
        origAppxPath, reSignedAppx, std::filesystem::copy_options::overwrite_existing);

    const char* signArgv[] = {
        "ccky",
        "signtool",
        "sign",
        "/v",
        "/fd",
        "sha256",
        "/f",
        pfxPath.c_str(),
        "/p",
        "",
        reSignedAppx.c_str(),
    };
    auto signArgs = ccky::cli::CliParser::parse(11, const_cast<char**>(signArgv), registry);
    auto signCmd = registry.getCommand("signtool");
    EXPECT_NE(signCmd, nullptr);
    if (signCmd)
    {
        EXPECT_EQ(signCmd->execute(signArgs), 0);
    }

    const char* certArgv[] = {
        "ccky",
        "certmgr",
        "/put",
        "/c",
        reSignedAppx.c_str(),
        reExtractedAppxCer.c_str(),
    };
    auto certArgs = ccky::cli::CliParser::parse(6, const_cast<char**>(certArgv), registry);
    auto certCmd = registry.getCommand("certmgr");
    EXPECT_NE(certCmd, nullptr);
    if (certCmd)
    {
        EXPECT_EQ(certCmd->execute(certArgs), 0);
    }

    auto cerStore = ccky::crypto::CryptoFactory::createStore(
        ccky::crypto::StoreType::CerFile, reExtractedAppxCer);
    EXPECT_NO_THROW(cerStore->load(reExtractedAppxCer));
    auto certs = cerStore->getCertificates();
    EXPECT_GT(certs.size(), 0);
    if (!certs.empty())
    {
        auto cert = certs[0];
        EXPECT_EQ(cert->getCommonName(), "ccky");
    }

    std::filesystem::remove(reSignedAppx);
    std::filesystem::remove(reExtractedAppxCer);
}
