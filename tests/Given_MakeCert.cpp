#include <array>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "cli/CliParser.h"
#include "commands/MakeCertCommand.h"
#include "crypto/CryptoFactory.h"
#include "crypto/ICertStore.h"
#include "crypto/PvkKey.h"

namespace
{
std::string stripPasswordPrompts(const std::string& str)
{
    std::string result = str;
    auto replaceAll =
        [](std::string& s, const std::string& toReplace, const std::string& replaceWith)
    {
        size_t pos = 0;
        while ((pos = s.find(toReplace, pos)) != std::string::npos)
        {
            s.replace(pos, toReplace.length(), replaceWith);
            pos += replaceWith.length();
        }
    };
    replaceAll(result, "Key:              Subject Key\n", "");
    replaceAll(result, "Key:              Issuer Signature\n", "");
    replaceAll(result, "Password:         ", "");
    replaceAll(result, "Confirm Password: ", "");
    replaceAll(result, "Key:      Subject Key\n", "");
    replaceAll(result, "Password: ", "");
    return result;
}
} // namespace

class Given_MakeCert : public CckyTest
{
  protected:
    std::string tempDir;

    void SetUp() override { CckyTest::SetUp(); }

    void TearDown() override
    {
        m_cleaners.clear();
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
            tempDir = "temp_makecert_test";
            std::filesystem::create_directories(tempDir);
        }
        return tempDir;
    }

  private:
    bool parseCertTime(const std::string& timeStr, std::tm& tm)
    {
        std::istringstream ss(timeStr);
        ss >> std::get_time(&tm, "%a %b %d %H:%M:%S %Y");
        return !ss.fail();
    }

  protected:
    int getMonthDifference(const std::string& notBeforeStr, const std::string& notAfterStr)
    {
        std::tm tm1 = {};
        std::tm tm2 = {};
        if (!parseCertTime(notBeforeStr, tm1) || !parseCertTime(notAfterStr, tm2))
        {
            return -1;
        }
        return (tm2.tm_year - tm1.tm_year) * 12 + (tm2.tm_mon - tm1.tm_mon);
    }

    void createCertWithPvk(const std::string& pvkPath, const std::string& certPath,
        const std::string& subject = "", const std::string& password = "password123")
    {
        std::stringstream out, err;
        std::stringstream in(password + "\n" + password + "\n" + password + "\n");
        auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
        cmd->setRegistry(&registry);
        std::vector<const char*> argv_vec = {
            "ccky",
            "makecert",
            "-sv",
            pvkPath.c_str(),
        };
        if (!subject.empty())
        {
            argv_vec.push_back("-n");
            argv_vec.push_back(subject.c_str());
        }
        argv_vec.push_back(certPath.c_str());
        auto args = ccky::cli::CliParser::parse(
            argv_vec.size(), const_cast<char**>(argv_vec.data()), registry);
        ASSERT_EQ(cmd->execute(args), 0) << "Setup Error: " << err.str();
    }

    void createCACert(const std::string& pvkPath, const std::string& certPath,
        const std::string& subject = "", const std::string& password = "password123")
    {
        std::stringstream out, err;
        std::stringstream in(password + "\n" + password + "\n" + password + "\n");
        auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
        cmd->setRegistry(&registry);
        std::vector<const char*> argv_vec = {
            "ccky",
            "makecert",
            "-sv",
            pvkPath.c_str(),
            "-cy",
            "authority",
        };
        if (!subject.empty())
        {
            argv_vec.push_back("-n");
            argv_vec.push_back(subject.c_str());
        }
        argv_vec.push_back(certPath.c_str());
        auto args = ccky::cli::CliParser::parse(
            argv_vec.size(), const_cast<char**>(argv_vec.data()), registry);
        ASSERT_EQ(cmd->execute(args), 0) << "Setup Error: " << err.str();
    }

    ccky::crypto::CertificatePtr findCertInStore(
        const std::string& commonName, const std::string& storeName = "My")
    {
        auto store =
            ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, storeName);
        store->load(storeName);
        auto certs = store->getCertificates();
        for (const auto& cert : certs)
        {
            if (cert->getCommonName() == commonName)
            {
                registerSystemStoreCert(storeName, cert->getSha1());
                return cert;
            }
        }
        return nullptr;
    }

    std::string createCACertInStore(const std::string& commonName, const std::string& certPath)
    {
        std::stringstream out, err;
        auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
        cmd->setRegistry(&registry);
        std::string subjectName = "CN=" + commonName;
        const char* argv[] = {
            "ccky",
            "makecert",
            "-ss",
            "My",
            "-cy",
            "authority",
            "-n",
            subjectName.c_str(),
            certPath.c_str(),
        };
        auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);
        if (cmd->execute(args) != 0)
        {
            return "";
        }
        auto cert = findCertInStore(commonName);
        return cert ? cert->getSha1() : "";
    }

    void registerTemporaryCerFile(const std::string& certPath)
    {
        class CckyCerFileCleaner : public CckyCleaner
        {
          public:
            explicit CckyCerFileCleaner(const std::string& path) : m_certPath(path) {}
            ~CckyCerFileCleaner() override
            {
                if (std::filesystem::exists(m_certPath))
                {
                    try
                    {
                        auto store = ccky::crypto::CryptoFactory::createStore(
                            ccky::crypto::StoreType::CerFile, m_certPath);
                        store->load(m_certPath);
                        auto certs = store->getCertificates();
                        if (certs.size() == 1)
                        {
                            std::string container = certs[0]->getContainerName();
                            if (!container.empty())
                            {
                                ccky::crypto::CryptoFactory::deleteKeyContainer(container);
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        GTEST_LOG_(WARNING)
                            << "Failed to delete key container during cleanup: " << e.what();
                    }
                    catch (...)
                    {
                        GTEST_LOG_(WARNING) << "Failed to delete key container during cleanup due "
                                               "to unknown exception";
                    }

                    std::filesystem::remove(m_certPath);
                }
            }

          private:
            std::string m_certPath;
        };

        m_cleaners.push_back(std::make_unique<CckyCerFileCleaner>(certPath));
    }

    void createBaseCert(const std::string& certPath, const std::string& subjectName,
        const std::string& containerName)
    {
        std::stringstream out, err;
        auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
        cmd->setRegistry(&registry);
        std::array argv = {
            "ccky",
            "makecert",
            "-sk",
            containerName.c_str(),
            "-n",
            subjectName.c_str(),
            certPath.c_str(),
        };
        auto args =
            ccky::cli::CliParser::parse(argv.size(), const_cast<char**>(argv.data()), registry);
        ASSERT_EQ(cmd->execute(args), 0);
    }
};

TEST_F(Given_MakeCert, When_HelpBasic_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::array argv = {
        "ccky",
        "makecert",
        "/?",
    };
    auto args = ccky::cli::CliParser::parse(argv.size(), const_cast<char**>(argv.data()), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/makecert_helpbasic_stderr.txt"));
}

TEST_F(Given_MakeCert, When_HelpExtended_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-!",
    };
    auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/makecert_helpextended_stderr.txt"));
}

TEST_F(Given_MakeCert, When_MissingArgs_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
    };
    auto args = ccky::cli::CliParser::parse(2, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/makecert_missingargs_stderr.txt"));
}

TEST_F(Given_MakeCert, When_BadDate_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-e",
        "baddate",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/makecert_baddate_stderr.txt"));
}

TEST_F(Given_MakeCert, When_MakeCertDefault_CreatesExpectedCert)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/default.cer";
    registerTemporaryCerFile(outCer);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-r",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, outCer);
    store->load(outCer);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(out.str(), getTestTextContent("tests/data/output/makecert_stdout.txt"));
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSubjectDN(), ccky::commands::MAKECERT_DEFAULT_SUBJECT_NAME);
    EXPECT_EQ(certs[0]->getNotAfter(), "Sat Dec 31 23:59:59 2039");
}

TEST_F(Given_MakeCert, When_BadEkuSpecified_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/bad_eku.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-r",
        "-eku",
        "bad",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(out.str(), getTestTextContent("tests/data/output/makecert_badeku_stdout.txt"));
    EXPECT_EQ(err.str(), "");
}

TEST_F(Given_MakeCert, When_EndDateSpecified_CreatesCertWithSpecifiedEndDate)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/end_date.cer";
    registerTemporaryCerFile(outCer);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-e",
        "05/20/2030",
        "-r",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, outCer);
    store->load(outCer);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    std::string notAfter = certs[0]->getNotAfter();
    EXPECT_NE(notAfter.find("May"), std::string::npos);
    EXPECT_NE(notAfter.find("20"), std::string::npos);
    EXPECT_NE(notAfter.find("2030"), std::string::npos);
}

TEST_F(Given_MakeCert, When_BadDateSlash_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-e",
        "31/12/2039",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), getTestTextContent("tests/data/output/makecert_baddate_stderr.txt"));
}

TEST_F(Given_MakeCert, When_ExistingPvk_UsesSameKey)
{
    std::string pvkPath = getTempDir() + "/existing.pvk";
    std::string certPath1 = getTempDir() + "/cert1.cer";
    std::string certPath2 = getTempDir() + "/cert2.cer";
    createCertWithPvk(pvkPath, certPath1);
    std::stringstream out, err;
    std::stringstream in("password123\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        certPath2.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store1 =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath1);
    store1->load(certPath1);
    auto certs1 = store1->getCertificates();
    auto store2 =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath2);
    store2->load(certPath2);
    auto certs2 = store2->getCertificates();

    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(stripPasswordPrompts(err.str()).empty());
    ASSERT_EQ(certs1.size(), 1);
    ASSERT_EQ(certs2.size(), 1);
    EXPECT_EQ(certs1[0]->getKeyMd5Thumbprint(), certs2[0]->getKeyMd5Thumbprint());
}

TEST_F(Given_MakeCert, When_SkySignature_CreatesSignatureKey)
{
    std::string pvkPath = getTempDir() + "/sig.pvk";
    std::string certPath = getTempDir() + "/sig.cer";
    std::stringstream out, err;
    std::stringstream in("password123\npassword123\npassword123\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        "-sky",
        "signature",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    ccky::crypto::PvkKey pvk;
    pvk.load(pvkPath);
    pvk.decrypt("password123");
    const auto& keyData = pvk.getKeyData();
    uint32_t aiKeyAlg = 0;
    if (keyData.size() >= 8)
    {
        aiKeyAlg = keyData[4] | (keyData[5] << 8) | (keyData[6] << 16) | (keyData[7] << 24);
    }

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pvk.getKeyType(), 2); // AT_SIGNATURE
    ASSERT_GE(keyData.size(), 8);
    EXPECT_EQ(aiKeyAlg, 0x00002400); // CALG_RSA_SIGN
}

TEST_F(Given_MakeCert, When_SkyExchange_CreatesExchangeKey)
{
    std::string pvkPath = getTempDir() + "/exch.pvk";
    std::string certPath = getTempDir() + "/exch.cer";
    std::stringstream out, err;
    std::stringstream in("password123\npassword123\npassword123\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        "-sky",
        "exchange",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    ccky::crypto::PvkKey pvk;
    pvk.load(pvkPath);
    pvk.decrypt("password123");
    const auto& keyData = pvk.getKeyData();
    uint32_t aiKeyAlg = 0;
    if (keyData.size() >= 8)
    {
        aiKeyAlg = keyData[4] | (keyData[5] << 8) | (keyData[6] << 16) | (keyData[7] << 24);
    }

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pvk.getKeyType(), 1); // AT_KEYEXCHANGE
    ASSERT_GE(keyData.size(), 8);
    EXPECT_EQ(aiKeyAlg, 0x0000a400); // CALG_RSA_KEYX
}

TEST_F(Given_MakeCert, When_SkyAuthority_CreatesCACert)
{
    std::string pvkPath = getTempDir() + "/ca.pvk";
    std::string certPath = getTempDir() + "/ca.cer";
    std::stringstream out, err;
    std::stringstream in("password123\npassword123\npassword123\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        "-cy",
        "authority",
        "-h",
        "3",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_TRUE(certs[0]->isCA());
    EXPECT_EQ(certs[0]->getPathLenConstraint(), 3);
}

TEST_F(Given_MakeCert, When_SkyEnd_CreatesEndEntityCert)
{
    std::string pvkPath = getTempDir() + "/end.pvk";
    std::string certPath = getTempDir() + "/end.cer";
    std::stringstream out, err;
    std::stringstream in("password123\npassword123\npassword123\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        "-cy",
        "end",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_FALSE(certs[0]->isCA());
    EXPECT_EQ(certs[0]->getPathLenConstraint(), 0);
}

TEST_F(Given_MakeCert, When_StoreSpecified_SavesToStore)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Store options are not supported on OpenSSL";
    }
    std::string certPath = getTempDir() + "/store_test.cer";
    std::string commonName = "CckyMakeCertStoreTest";
    std::string subjectName = "CN=" + commonName;
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ss",
        "My",
        "-n",
        subjectName.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto cert = findCertInStore(commonName);

    EXPECT_EQ(ret, 0);
    EXPECT_NE(cert, nullptr);
}

TEST_F(Given_MakeCert, When_PeSpecified_KeyIsExportable)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Store/Provider options are not supported on OpenSSL";
    }
    std::string certPath = getTempDir() + "/pe_test.cer";
    std::string commonName = "CckyMakeCertPeTest";
    std::string subjectName = "CN=" + commonName;
    std::string containerName = "CckyTestContainerPe";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ss",
        "My",
        "-sk",
        containerName.c_str(),
        "-pe",
        "-n",
        subjectName.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto foundCert = findCertInStore(commonName);

    ASSERT_NE(foundCert, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(foundCert->getContainerName(), containerName);
    EXPECT_TRUE(foundCert->isPrivateKeyExportable());
}

TEST_F(Given_MakeCert, When_PeNotSpecified_KeyIsNotExportable)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Store/Provider options are not supported on OpenSSL";
    }
    std::string certPath = getTempDir() + "/no_pe_test.cer";
    std::string commonName = "CckyMakeCertNoPeTest";
    std::string subjectName = "CN=" + commonName;
    std::string containerName = "CckyTestContainerNoPe";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ss",
        "My",
        "-sk",
        containerName.c_str(),
        "-n",
        subjectName.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto foundCert = findCertInStore(commonName);

    ASSERT_NE(foundCert, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_FALSE(foundCert->isPrivateKeyExportable());
}

TEST_F(Given_MakeCert, When_IssuerCertAndPvkSpecified_CreatesSignedCert)
{
    std::string caPvkPath = getTempDir() + "/ca.pvk";
    std::string caCertPath = getTempDir() + "/ca.cer";
    std::string childPvkPath = getTempDir() + "/child.pvk";
    std::string childCertPath = getTempDir() + "/child.cer";
    createCACert(caPvkPath, caCertPath, "CN=CckyTestCA", "capass");
    std::stringstream out, err;
    std::stringstream in("childpass\nchildpass\nchildpass\ncapass\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ic",
        caCertPath.c_str(),
        "-iv",
        caPvkPath.c_str(),
        "-sv",
        childPvkPath.c_str(),
        "-n",
        "CN=CckyTestChild",
        childCertPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(11, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, childCertPath);
    store->load(childCertPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getIssuerName(), "CckyTestCA");
    EXPECT_EQ(certs[0]->getCommonName(), "CckyTestChild");
}

TEST_F(Given_MakeCert, When_IssuerPvkIncorrectPassword_MatchesOutput)
{
    std::string caPvkPath = "issuer.pvk";
    std::string caCertPath = "issuer.cer";
    std::string childPvkPath = getTempDir() + "/child_err.pvk";
    std::string childCertPath = getTempDir() + "/child_err.cer";
    createCACert(caPvkPath, caCertPath, "CN=CckyTestCAErr", "capass");
    registerTemporaryFile(caPvkPath);
    registerTemporaryFile(caCertPath);
    std::stringstream out, err;
    std::stringstream in("childpass\nchildpass\nchildpass\nWRONGpass\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ic",
        caCertPath.c_str(),
        "-iv",
        caPvkPath.c_str(),
        "-sv",
        childPvkPath.c_str(),
        "-n",
        "CN=CckyTestChildErr",
        childCertPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(11, const_cast<char**>(argv), registry);
    std::string expectedErr = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_issuerpvkbadpassword_stderr.txt"));
    std::string expectedOut = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_issuerpvkbadpassword_stdout.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(stripPasswordPrompts(err.str()), expectedErr);
    EXPECT_EQ(out.str(), expectedOut);
}

TEST_F(Given_MakeCert, When_IssuerStoreSpecified_CreatesSignedCert)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Store options are not supported on OpenSSL";
    }
    std::string childCertPath = getTempDir() + "/child_store.cer";
    registerTemporaryCerFile(childCertPath);
    std::string caCommonName = "CckyTestCAWin";
    std::string caSubjectName = "CN=" + caCommonName;
    std::string childCommonName = "CckyTestChildWin";
    std::string childSubjectName = "CN=" + childCommonName;
    std::string caStoreCertPath = getTempDir() + "/ca_store.cer";
    std::string caHash = createCACertInStore(caCommonName, caStoreCertPath);
    ASSERT_FALSE(caHash.empty());
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-is",
        "My",
        "-in",
        caCommonName.c_str(),
        "-n",
        childSubjectName.c_str(),
        childCertPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, childCertPath);
    store->load(childCertPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getIssuerName(), caCommonName);
    EXPECT_EQ(certs[0]->getCommonName(), childCommonName);
}

TEST_F(Given_MakeCert, When_EkuSpecified_CreatesCertWithEku)
{
    std::string certPath = getTempDir() + "/eku_test.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-eku",
        "1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.1,clientAuth",
        "-n",
        "CN=EkuTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    std::vector<std::string> eku = certs[0]->getEnhancedKeyUsage();
    ASSERT_EQ(eku.size(), 3);
    EXPECT_EQ(eku[0], "1.3.6.1.5.5.7.3.3");
    EXPECT_EQ(eku[1], "1.3.6.1.5.5.7.3.1");
    EXPECT_EQ(eku[2], "1.3.6.1.5.5.7.3.2");
}

TEST_F(Given_MakeCert, When_SubjectCertSpecified_UsesItsPublicKey)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Subject cert key resolution without PVK is only supported on Windows "
                        "(requires CSP)";
    }
    std::string baseCertPath = getTempDir() + "/base.cer";
    std::string testCertPath = getTempDir() + "/test_sc.cer";
    std::string containerName = "CckyTestContainerBaseSC";
    createBaseCert(baseCertPath, "CN=Base", containerName);
    registerKeyContainer(containerName);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sc",
        baseCertPath.c_str(),
        "-n",
        "CN=TestSC",
        testCertPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store1 =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, baseCertPath);
    store1->load(baseCertPath);
    auto certs1 = store1->getCertificates();
    auto store2 =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, testCertPath);
    store2->load(testCertPath);
    auto certs2 = store2->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs1.size(), 1);
    ASSERT_EQ(certs2.size(), 1);
    EXPECT_EQ(certs1[0]->getKeySha256Thumbprint(), certs2[0]->getKeySha256Thumbprint());
}

TEST_F(Given_MakeCert, When_SubjectCertInvalid_Throws)
{
    std::string invalidCertPath = getTempDir() + "/invalid.cer";
    {
        std::ofstream f(invalidCertPath, std::ios::binary);
        f << "not a valid der certificate";
    }
    std::string testCertPath = getTempDir() + "/test_invalid_sc.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sc",
        invalidCertPath.c_str(),
        "-n",
        "CN=TestInvalidSC",
        testCertPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_NE(ret, 0);
    EXPECT_TRUE(err.str().find("Can't access the certificate of the subject") != std::string::npos);
}

TEST_F(Given_MakeCert, When_PolicyLinkSpecified_CreatesCertWithPolicy)
{
    std::string certPath = getTempDir() + "/policy_test.cer";
    registerTemporaryCerFile(certPath);
    std::string policyUrl = "http://example.com/cps";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-l",
        policyUrl.c_str(),
        "-n",
        "CN=PolicyTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getPolicyLink(), policyUrl);
}

TEST_F(Given_MakeCert, When_NetscapeSpecified_CreatesCertWithNetscape)
{
    std::string certPath = getTempDir() + "/nscp_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-nscp",
        "-n",
        "CN=NscpTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(6, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getNetscapeCertType() & 0x80, 0x80);
}

TEST_F(Given_MakeCert, When_AuthorityCommercialSpecified_CreatesCommercialCert)
{
    std::string certPath = getTempDir() + "/commercial_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-$",
        "commercial",
        "-n",
        "CN=CommercialTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    std::vector<std::string> eku = certs[0]->getEnhancedKeyUsage();
    ASSERT_EQ(eku.size(), 1);
    EXPECT_EQ(eku[0], "1.3.6.1.4.1.311.2.1.22");
}

TEST_F(Given_MakeCert, When_AuthorityIndividualSpecified_CreatesIndividualCert)
{
    std::string certPath = getTempDir() + "/individual_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-$",
        "individual",
        "-n",
        "CN=IndividualTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    std::vector<std::string> eku = certs[0]->getEnhancedKeyUsage();
    ASSERT_EQ(eku.size(), 1);
    EXPECT_EQ(eku[0], "1.3.6.1.4.1.311.2.1.21");
}

TEST_F(Given_MakeCert, When_LenSpecified_CreatesCertWithSpecifiedKeyLength)
{
    std::string certPath = getTempDir() + "/len_4096_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-len",
        "4096",
        "-n",
        "CN=Len4096Test",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getKeyLength(), 4096);
}

TEST_F(Given_MakeCert, When_LenDefaultRsa_CreatesCertWith2048Bits)
{
    std::string certPath = getTempDir() + "/len_default_rsa_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-n",
        "CN=LenDefaultRsaTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getKeyLength(), 2048);
}

TEST_F(Given_MakeCert, When_LenDefaultDss_CreatesCertWith512Bits)
{
    std::string certPath = getTempDir() + "/len_default_dss_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sy",
        "3",
        "-n",
        "CN=LenDefaultDssTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        EXPECT_EQ(certs[0]->getKeyLength(), 1024);
    }
    else
    {
        EXPECT_EQ(certs[0]->getKeyLength(), 512);
    }
}

TEST_F(Given_MakeCert, When_DigestAlgorithmSpecified_UsesSpecifiedAlgorithm)
{
    std::string certPath = getTempDir() + "/algo_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-a",
        "sha256",
        "-n",
        "CN=AlgoTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSignatureAlgorithm(), "1.2.840.113549.1.1.11");
}

TEST_F(Given_MakeCert, When_ProviderSpecified_UsesSpecifiedProvider)
{
    if (ccky::crypto::CryptoFactory::getBackendType() == "openssl")
    {
        GTEST_SKIP() << "Store/Provider options are not supported on OpenSSL";
    }
    std::string certPath = getTempDir() + "/prov_test.cer";
    std::string commonName = "CckyProvTest";
    std::string subjectName = "CN=" + commonName;
    std::string containerName = "CckyTestContainerProv";
    std::string provName = "Microsoft Enhanced Cryptographic Provider v1.0";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ss",
        "My",
        "-sk",
        containerName.c_str(),
        "-sp",
        provName.c_str(),
        "-sy",
        "1",
        "-n",
        subjectName.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(13, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto foundCert = findCertInStore(commonName);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(foundCert, nullptr);
    EXPECT_EQ(foundCert->getProviderName(), provName);
    EXPECT_EQ(foundCert->getProviderType(), "1");
    EXPECT_EQ(foundCert->getContainerName(), containerName);
}

TEST_F(Given_MakeCert, When_InvalidProviderType_Throws)
{
    std::string certPath = getTempDir() + "/invalid_prov_test.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sy",
        "99",
        "-n",
        "CN=InvalidProvTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_NE(ret, 0);
    EXPECT_TRUE(err.str().find("Can't create the key of the subject") != std::string::npos);
}

TEST_F(Given_MakeCert, When_DssKeyExchange_Throws)
{
    std::string certPath = getTempDir() + "/dss_kx_test.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sy",
        "3",
        "-sky",
        "exchange",
        "-n",
        "CN=DssKxTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(9, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    // TODO: Add output file for this case and convert to a "_MatchesOutput" test.
    EXPECT_NE(ret, 0);
    EXPECT_EQ(err.str(), "Error: Can't create the key of the subject\n");
}

TEST_F(Given_MakeCert, When_SerialNumberSpecified_CreatesCertWithSerialNumber)
{
    std::string certPath = getTempDir() + "/serial_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-#",
        "12345",
        "-n",
        "CN=SerialTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs[0]->getSerialNumber(), "30 39");
}

TEST_F(Given_MakeCert, When_MonthsSpecified_CreatesCertWithValidityDuration)
{
    std::string certPath = getTempDir() + "/months_test.cer";
    registerTemporaryCerFile(certPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-m",
        "6",
        "-n",
        "CN=MonthsTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, certPath);
    store->load(certPath);
    auto certs = store->getCertificates();

    EXPECT_EQ(ret, 0);
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(getMonthDifference(certs[0]->getNotBefore(), certs[0]->getNotAfter()), 6);
}

TEST_F(Given_MakeCert, When_InvalidSky_Throws)
{
    std::string certPath = getTempDir() + "/invalid_sky_test.cer";
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sky",
        "3",
        "-n",
        "CN=InvalidSkyTest",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);

    int ret = cmd->execute(args);

    EXPECT_NE(ret, 0);
    EXPECT_TRUE(err.str().find("Can't create the key of the subject") != std::string::npos);
}

TEST_F(Given_MakeCert, When_BadStartDate_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-b",
        "baddate",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_badstartdate_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_IvWithoutIc_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-iv",
        "issuer.pvk",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_ivwithoutic_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_TwoFilesSpecified_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "file1.cer",
        "file2.cer",
    };
    auto args = ccky::cli::CliParser::parse(4, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_twofiles_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_BadAuthority_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-$",
        "bad_authority",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_badauthority_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_IvAndIcWithR_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-r",
        "-ic",
        "issuer.cer",
        "-iv",
        "issuer.pvk",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(8, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_ivicwithr_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_ExistingPvkBadPassword_MatchesOutput)
{
    std::string pvkPath = "test.pvk";
    std::string certPath = getTempDir() + "/temp.cer";
    createCertWithPvk(pvkPath, certPath);
    registerTemporaryFile(pvkPath);
    std::stringstream out, err;
    std::stringstream in("WRONGpass\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expectedErr = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_existingpvkbadpassword_stderr.txt"));
    std::string expectedOut = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_existingpvkbadpassword_stdout.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(stripPasswordPrompts(err.str()), expectedErr);
    EXPECT_EQ(out.str(), expectedOut);
}

TEST_F(Given_MakeCert, When_IcOnly_MatchesStderr)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-ic",
        "issuer.cer",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expected =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_iconly_stderr.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expected);
}

TEST_F(Given_MakeCert, When_BadSubjectProvider_MatchesOutput)
{
    std::string pvkPath = "test.pvk";
    std::string certPath = getTempDir() + "/temp.cer";
    registerTemporaryFile(pvkPath);
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        "-sy",
        "99",
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    std::string expectedErr = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_badsubjectprovider_stderr.txt"));
    std::string expectedOut = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_badsubjectprovider_stdout.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(err.str(), expectedErr);
    EXPECT_EQ(out.str(), expectedOut);
}

TEST_F(Given_MakeCert, When_NewPvkSecondPromptBadPassword_MatchesOutput)
{
    std::string pvkPath = "test.pvk";
    std::string certPath = getTempDir() + "/temp.cer";
    std::filesystem::remove(certPath);
    registerTemporaryFile(pvkPath);
    std::stringstream out, err;
    std::stringstream in("pass1\npass1\npass2\n");
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(in, out, err);
    cmd->setRegistry(&registry);
    const char* argv[] = {
        "ccky",
        "makecert",
        "-sv",
        pvkPath.c_str(),
        certPath.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(5, const_cast<char**>(argv), registry);
    std::string expectedErr = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_newpvksecondpromptbadpassword_stderr.txt"));
    std::string expectedOut = getTestTextContent(
        getTestDataPath("tests/data/output/makecert_newpvksecondpromptbadpassword_stdout.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_EQ(stripPasswordPrompts(err.str()), expectedErr);
    EXPECT_EQ(out.str(), expectedOut);
    EXPECT_TRUE(std::filesystem::exists(pvkPath));
    EXPECT_FALSE(std::filesystem::exists(certPath));
}

TEST_F(Given_MakeCert, When_EAndMSpecified_MatchesOutput)
{
    std::stringstream out, err;
    auto cmd = std::make_shared<ccky::commands::MakeCertCommand>(std::cin, out, err);
    cmd->setRegistry(&registry);
    std::string outCer = getTempDir() + "/output.cer";
    const char* argv[] = {
        "ccky",
        "makecert",
        "-e",
        "01/01/2026",
        "-m",
        "12",
        outCer.c_str(),
    };
    auto args = ccky::cli::CliParser::parse(7, const_cast<char**>(argv), registry);
    std::string expectedOut =
        getTestTextContent(getTestDataPath("tests/data/output/makecert_eandm_stdout.txt"));

    int ret = cmd->execute(args);

    EXPECT_EQ(ret, 1);
    EXPECT_TRUE(err.str().empty());
    EXPECT_EQ(out.str(), expectedOut);
}
