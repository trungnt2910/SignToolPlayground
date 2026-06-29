#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/CryptoFactory.h"

class Given_CryptoFactory : public CckyTest
{
};

TEST_F(Given_CryptoFactory, When_CreateStoreWithCer_ReturnsCerStore)
{
    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");

    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, cerPath);

    EXPECT_NE(store, nullptr);
    EXPECT_EQ(store->getStoreType(), ccky::crypto::StoreType::CerFile);
}

TEST_F(Given_CryptoFactory, When_CalculateSha256_ReturnsHash)
{
    std::string path = getTestDataPath("tests/data/test.exe");

    std::string hash = ccky::crypto::CryptoFactory::calculateSha256(path);

    EXPECT_EQ(hash, "592C1A2FA449F9617FF60AB3EDC3776ED5507A45616237EF472DCA839C0356CF");
}
