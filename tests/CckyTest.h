#pragma once

#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "cli/CommandRegistry.h"
#include "commands/CertMgrCommand.h"
#include "commands/MakeCertCommand.h"
#include "commands/Pvk2PfxCommand.h"
#include "commands/SignToolCommand.h"
#include "crypto/Certificate.h"
#include "crypto/CertificateStore.h"
#include "crypto/CryptoFactory.h"
#include "crypto/FileTypeDetector.h"
#include "crypto/TimeFormatter.h"

class CckyCleaner
{
  public:
    virtual ~CckyCleaner() = default;
};

class CckyTest : public ::testing::Test
{
  protected:
    std::vector<std::unique_ptr<CckyCleaner>> m_cleaners;
    std::vector<ccky::crypto::CertificateStorePtr> m_activeStores;

    void SetUp() override
    {
        ccky::crypto::TimeFormatter::setFormatUTC(true);
        registry.registerCommand(std::make_shared<ccky::commands::CertMgrCommand>());
        registry.registerCommand(std::make_shared<ccky::commands::MakeCertCommand>());
        registry.registerCommand(std::make_shared<ccky::commands::Pvk2PfxCommand>());
        registry.registerCommand(std::make_shared<ccky::commands::SignToolCommand>());
    }

    void TearDown() override
    {
        m_cleaners.clear();
        ::testing::Test::TearDown();
    }

    std::string getTestDataPath(const std::string& relPath) { return relPath; }

    std::string getTestTextContent(const std::string& relPath)
    {
        std::string path = getTestDataPath(relPath);
        std::ifstream f(path);
        if (!f.is_open())
        {
            ADD_FAILURE() << "Failed to open test data file: " << relPath;
            return "";
        }
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return content;
    }

    void expectFilesEqual(const std::string& expectedPath, const std::string& actualPath)
    {
        std::ifstream expectedFile(expectedPath, std::ios::binary);
        std::ifstream actualFile(actualPath, std::ios::binary);

        ASSERT_TRUE(expectedFile.is_open()) << "Failed to open expected file: " << expectedPath;
        ASSERT_TRUE(actualFile.is_open()) << "Failed to open actual file: " << actualPath;

        std::vector<uint8_t> expectedBytes(
            (std::istreambuf_iterator<char>(expectedFile)), std::istreambuf_iterator<char>());
        std::vector<uint8_t> actualBytes(
            (std::istreambuf_iterator<char>(actualFile)), std::istreambuf_iterator<char>());

        EXPECT_EQ(expectedBytes, actualBytes);
    }

    void registerTemporaryFile(const std::string& path)
    {
        class CckyFileCleaner : public CckyCleaner
        {
          public:
            explicit CckyFileCleaner(const std::string& p) : m_path(p) {}
            ~CckyFileCleaner() override
            {
                if (std::filesystem::exists(m_path))
                {
                    std::filesystem::remove(m_path);
                }
            }

          private:
            std::string m_path;
        };

        m_cleaners.push_back(std::make_unique<CckyFileCleaner>(path));
    }

    void registerKeyContainer(
        const std::string& name, const std::string& provName = "", uint32_t provType = 0)
    {
        class CckyKeyContainerCleaner : public CckyCleaner
        {
          public:
            CckyKeyContainerCleaner(const std::string& n, const std::string& pn, uint32_t pt)
                : m_name(n), m_provName(pn), m_provType(pt)
            {
            }
            ~CckyKeyContainerCleaner() override
            {
                ccky::crypto::CryptoFactory::deleteKeyContainer(m_name, m_provName, m_provType);
            }

          private:
            std::string m_name;
            std::string m_provName;
            uint32_t m_provType;
        };

        m_cleaners.push_back(std::make_unique<CckyKeyContainerCleaner>(name, provName, provType));
    }

    void registerSystemStoreCert(const std::string& storeName, const std::string& commonName,
        const std::string& thumbprint = "")
    {
        class CckySystemStoreCertCleaner : public CckyCleaner
        {
          public:
            CckySystemStoreCertCleaner(
                const std::string& s, const std::string& c, const std::string& t)
                : m_storeName(s), m_commonName(c), m_thumbprint(t)
            {
            }
            ~CckySystemStoreCertCleaner() override
            {
                if (ccky::crypto::CryptoFactory::getBackendType() == "windows")
                {
                    try
                    {
                        auto store = ccky::crypto::CryptoFactory::createStore(
                            ccky::crypto::StoreType::WinSystem, m_storeName);
                        store->load(m_storeName);
                        store->deleteCertificate(m_commonName, m_thumbprint);
                    }
                    catch (const std::exception& e)
                    {
                        GTEST_LOG_(WARNING)
                            << "Failed to delete certificate during cleanup: " << e.what();
                    }
                }
            }

          private:
            std::string m_storeName;
            std::string m_commonName;
            std::string m_thumbprint;
        };

        m_cleaners.push_back(
            std::make_unique<CckySystemStoreCertCleaner>(storeName, commonName, thumbprint));
    }

    std::vector<ccky::crypto::CertificatePtr> registerSystemStoreCertFromFile(
        const std::string& storeName, const std::string& filePath, const std::string& password = "")
    {
        auto type = ccky::crypto::FileTypeDetector::detectFileType(filePath);
        auto store = ccky::crypto::CryptoFactory::createStore(type, filePath);
        if (!store)
        {
            return {};
        }
        ccky::crypto::StoreOptions opts;
        opts.password = password;
        store->load(filePath, opts);
        auto certs = store->getCertificates();
        for (const auto& cert : certs)
        {
            registerSystemStoreCert(storeName, cert->getCommonName(), cert->getSha1());
        }
        // Keep the certificate store (which, for PFX files, owns the private keys) alive.
        // certmgr /add and CertificateStore::addCertificate do not actually keep the private keys.
        // To make the installed certificate usable, the system relies on the temporary PFX key
        // container that we are holding.
        m_activeStores.emplace_back(std::move(store));
        return certs;
    }

    std::vector<ccky::crypto::CertificatePtr> installSystemStoreCert(
        const std::string& storeName, const std::string& filePath, const std::string& password = "")
    {
        auto certs = registerSystemStoreCertFromFile(storeName, filePath, password);
        if (certs.empty() || ccky::crypto::CryptoFactory::getBackendType() != "windows")
        {
            return certs;
        }
        auto sysStore =
            ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, storeName);
        EXPECT_NE(sysStore, nullptr) << "Failed to create WinSystem store: " << storeName;
        if (!sysStore)
        {
            return {};
        }
        sysStore->load(storeName);
        auto existingCerts = sysStore->getCertificates();
        for (const auto& cert : certs)
        {
            for (const auto& existing : existingCerts)
            {
                if (!cert->getCommonName().empty() &&
                    existing->getCommonName() == cert->getCommonName())
                {
                    ADD_FAILURE() << "Cannot install certificate '" << cert->getCommonName()
                                  << "' into store '" << storeName
                                  << "': a certificate with the same Common Name already exists "
                                     "(existing SHA1='"
                                  << existing->getSha1() << "')";
                    return {};
                }
            }
            sysStore->addCertificate(cert);
        }
        return certs;
    }

    void reserveSystemStoreCertName(const std::string& storeName, const std::string& commonName)
    {
        if (ccky::crypto::CryptoFactory::getBackendType() != "windows")
        {
            return;
        }
        auto sysStore =
            ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::WinSystem, storeName);
        EXPECT_NE(sysStore, nullptr) << "Failed to create WinSystem store: " << storeName;
        if (!sysStore)
        {
            return;
        }
        sysStore->load(storeName);
        for (const auto& existing : sysStore->getCertificates())
        {
            if (!commonName.empty() && existing->getCommonName() == commonName)
            {
                ADD_FAILURE() << "Cannot reserve certificate Common Name '" << commonName
                              << "' in store '" << storeName
                              << "': a certificate with this Common Name already exists (SHA1='"
                              << existing->getSha1() << "')";
                return;
            }
        }
        registerSystemStoreCert(storeName, commonName);
    }

    ccky::cli::CommandRegistry registry;
};
