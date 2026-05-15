#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/AuthenticodeSigner.h"
#include "crypto/CryptoFactory.h"

class Given_PeStore : public CckyTest
{
};

TEST_F(Given_PeStore, When_LoadUnsignedPe_LoadsSuccessfully)
{
    std::string path = getTestDataPath("tests/data/test.exe");
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PeFile, path);
    EXPECT_NO_THROW(store->load(path));
    EXPECT_EQ(store->getStoreType(), ccky::crypto::StoreType::PeFile);
    EXPECT_EQ(store->getCertificates().size(), 0);
}

TEST_F(Given_PeStore, When_LoadSignedPe_ExtractsCertificates)
{
    std::string path = getTestDataPath("tests/data/lxmonika.sys");
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PeFile, path);
    EXPECT_NO_THROW(store->load(path));
    EXPECT_EQ(store->getStoreType(), ccky::crypto::StoreType::PeFile);
    EXPECT_GT(store->getCertificates().size(), 0);
}
