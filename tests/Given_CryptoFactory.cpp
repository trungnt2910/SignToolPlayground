#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/CryptoFactory.h"

class Given_CryptoFactory : public CckyTest
{
};

TEST_F(Given_CryptoFactory, When_CreateStoreAutoDetectsFileType)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string peDat = "test_pe.dat";
    std::filesystem::copy_file(
        origPePath, peDat, std::filesystem::copy_options::overwrite_existing);
    auto peStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, peDat);
    EXPECT_EQ(peStore->getStoreType(), ccky::crypto::StoreType::PeFile);
    std::filesystem::remove(peDat);

    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    auto pfxStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, pfxPath);
    EXPECT_EQ(pfxStore->getStoreType(), ccky::crypto::StoreType::PfxFile);

    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");
    auto cerStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, cerPath);
    EXPECT_EQ(cerStore->getStoreType(), ccky::crypto::StoreType::CerFile);
}
