#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/AuthenticodeSigner.h"
#include "crypto/CryptoFactory.h"

class Given_AppxStore : public CckyTest
{
};

TEST_F(Given_AppxStore, When_LoadSignedAppx_ExtractsCertificates)
{
    std::string path = getTestDataPath("tests/data/test.appx");
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, path);

    store->load(path);

    EXPECT_EQ(store->getStoreType(), ccky::crypto::StoreType::AppxFile);
    EXPECT_GT(store->getCertificates().size(), 0);
}

TEST_F(Given_AppxStore, When_SignAppx_PreservesExistingContent)
{
    std::string srcPath = getTestDataPath("tests/data/ccky.appx");
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    std::string outPath = "temp_appx_test.appx";
    registerTemporaryFile(outPath);
    std::filesystem::copy_file(srcPath, outPath, std::filesystem::copy_options::overwrite_existing);
    auto certStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PfxFile, pfxPath);
    ccky::crypto::StoreOptions opts;
    opts.password = "";
    certStore->load(pfxPath, opts);
    ASSERT_FALSE(certStore->getCertificates().empty());
    ccky::crypto::SignOptions signOpts;
    signOpts.fileDigestAlg = "SHA256";
    ccky::crypto::AuthenticodeSigner signer;

    signer.sign(certStore->getCertificates()[0], signOpts, outPath);

    auto verifyStore =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, outPath);
    verifyStore->load(outPath);
    EXPECT_EQ(verifyStore->getStoreType(), ccky::crypto::StoreType::AppxFile);
    EXPECT_GT(std::filesystem::file_size(outPath), 500000);
    EXPECT_GT(verifyStore->getCertificates().size(), 0);
}
