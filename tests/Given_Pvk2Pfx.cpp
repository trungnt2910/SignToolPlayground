#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"
#include "commands/Pvk2PfxCommand.h"
#include "crypto/Bytes.h"
#include "crypto/CertificateStore.h"
#include "crypto/CryptoFactory.h"
#include "crypto/PvkKey.h"

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

    void corruptPvkVersion(const std::string& inputPath, const std::string& outputPath)
    {
        std::ifstream file(inputPath, std::ios::binary);
        ASSERT_TRUE(file.is_open());

        std::vector<uint8_t> content(
            (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        ASSERT_GE(content.size(), 24);

        uint32_t saltLen = ccky::crypto::Bytes::readU32LE(content.data() + 16);

        size_t versionOffset = 24 + saltLen + 1;
        ASSERT_LT(versionOffset, content.size());

        content[versionOffset] = 0x00; // Corrupt it (must not be 0x02)

        std::ofstream outFile(outputPath, std::ios::binary);
        ASSERT_TRUE(outFile.is_open());
        outFile.write(reinterpret_cast<const char*>(content.data()), content.size());
    }
};

TEST_F(Given_Pvk2Pfx, When_Help_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_help_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_MissingArgs_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

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
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_filenotfound_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_BadPassword_MatchesStderr)
{
    std::string pvkPath = getTempDir() + "/temp_encrypted.pvk";
    std::string spcPath = getTempDir() + "/temp_encrypted.cer";
    {
        std::stringstream makeCertOut, makeCertErr;
        std::stringstream makeCertIn("realpassword\nrealpassword\nrealpassword\n");
        auto makeCertCmd =
            std::make_shared<ccky::commands::MakeCertCommand>(makeCertIn, makeCertOut, makeCertErr);
        makeCertCmd->setRegistry(&registry);
        std::array makeCertArgv = {
            "ccky",
            "makecert",
            "-sv",
            pvkPath.c_str(),
            spcPath.c_str(),
        };
        auto makeCertArgs =
            ccky::cli::CliParser::parse(makeCertArgv.size(), makeCertArgv.data(), registry);
        // Provide "realpassword\nrealpassword\nrealpassword\n" for PVK creation (Create, Confirm &
        // Reload)
        ASSERT_EQ(makeCertCmd->execute(makeCertArgs), 0);
    }
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string pfxPath = getTempDir() + "/out.pfx";
    std::array argv = {
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
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

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
    std::array argv = {
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
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

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
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

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
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/pvk2pfx_badfile_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_UnencryptedPvkBadVersion_MatchesStderr)
{
    std::string pvkPath = getTestDataPath("tests/data/ccky.pvk");
    std::string corruptPvkPath = getTempDir() + "/ccky_corrupt.pvk";
    registerTemporaryFile(corruptPvkPath);
    corruptPvkVersion(pvkPath, corruptPvkPath);
    std::string spcPath = getTestDataPath("tests/data/ccky.cer");
    std::string pfxPath = getTempDir() + "/out.pfx";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        corruptPvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(
        err.str(), getTestTextContent("tests/data/output/pvk2pfx_badproviderversion_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_EncryptedPvkBadVersion_MatchesStderr)
{
    std::string pvkPath = getTestDataPath("tests/data/1234.pvk");
    std::string corruptPvkPath = getTempDir() + "/1234_corrupt.pvk";
    registerTemporaryFile(corruptPvkPath);
    corruptPvkVersion(pvkPath, corruptPvkPath);
    std::string spcPath = getTestDataPath("tests/data/ccky.cer");
    std::string pfxPath = getTempDir() + "/out.pfx";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        corruptPvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
        "-pi",
        "1234",
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(
        err.str(), getTestTextContent("tests/data/output/pvk2pfx_badproviderversion_stderr.txt"));
}

TEST_F(Given_Pvk2Pfx, When_PoOmitted_UsesPvkPasswordForPfx)
{
    std::string pvkPath = getTestDataPath("tests/data/1234.pvk");
    std::string spcPath = getTestDataPath("tests/data/1234.cer");
    std::string pfxPath = getTempDir() + "/out_default_pw.pfx";
    registerTemporaryFile(pfxPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
        "-pi",
        "1234",
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PfxFile, pfxPath);
    ccky::crypto::StoreOptions options;
    options.password = "1234";
    store->load(pfxPath, options);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(err.str(), "");
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSubjectDN(), "CN=ccky");
}

TEST_F(Given_Pvk2Pfx, When_EncryptedPvkWithoutPi_PromptsForPassword)
{
    std::string pvkPath = getTestDataPath("tests/data/1234.pvk");
    std::string spcPath = getTestDataPath("tests/data/1234.cer");
    std::string pfxPath = getTempDir() + "/out_prompt_pw.pfx";
    registerTemporaryFile(pfxPath);
    std::stringstream in("1234\n");
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::Pvk2PfxCommand>(in, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "pvk2pfx",
        "-pvk",
        pvkPath.c_str(),
        "-spc",
        spcPath.c_str(),
        "-pfx",
        pfxPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), argv.data(), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PfxFile, pfxPath);
    ccky::crypto::StoreOptions options;
    options.password = "";
    store->load(pfxPath, options);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSubjectDN(), "CN=ccky");
    EXPECT_TRUE(certs[0]->hasPrivateKey());
    EXPECT_NE(certs[0]->getPrivateKey(), nullptr);
}
