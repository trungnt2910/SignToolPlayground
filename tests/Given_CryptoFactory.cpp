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
