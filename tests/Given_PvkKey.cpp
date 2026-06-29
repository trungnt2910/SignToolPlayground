#include <filesystem>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/PvkKey.h"

namespace
{

std::vector<uint8_t> getDummyRsa2Blob()
{
    // A dummy PRIVATEKEYBLOB that at least has RSA2 magic at offset 8
    std::vector<uint8_t> blob(16, 0);
    blob[0] = 0x07; // bType = PRIVATEKEYBLOB
    blob[1] = 0x02; // bVersion
    // offset 8 is magic "RSA2" = 0x32415352
    blob[8] = 0x52;
    blob[9] = 0x53;
    blob[10] = 0x41;
    blob[11] = 0x32;
    return blob;
}

} // namespace

class Given_PvkKey : public CckyTest
{
};

TEST_F(Given_PvkKey, When_LoadUnencryptedPvk_Succeeds)
{
    std::string pvkPath = getTestDataPath("tests/data/ccky.pvk");
    ccky::crypto::PvkKey pvk;

    pvk.load(pvkPath);
    pvk.decrypt("");

    EXPECT_FALSE(pvk.getKeyData().empty());
}

TEST_F(Given_PvkKey, When_SaveUnencryptedPvk_Succeeds)
{
    std::string outPath =
        (std::filesystem::temp_directory_path() / "temp_unencrypted.pvk").string();
    registerTemporaryFile(outPath);
    ccky::crypto::PvkKey pvk;
    pvk.setKeyData(getDummyRsa2Blob(), 1);
    ccky::crypto::PvkKey reloadedPvk;

    pvk.encrypt("");
    pvk.save(outPath);
    reloadedPvk.load(outPath);
    reloadedPvk.decrypt("");

    EXPECT_EQ(reloadedPvk.getKeyData(), getDummyRsa2Blob());
}

TEST_F(Given_PvkKey, When_SaveAndLoadEncryptedPvk_SucceedsWithPassword)
{
    std::string outPath = (std::filesystem::temp_directory_path() / "temp_encrypted.pvk").string();
    registerTemporaryFile(outPath);
    std::string password = "test_password";
    ccky::crypto::PvkKey pvk;
    pvk.setKeyData(getDummyRsa2Blob(), 1);
    ccky::crypto::PvkKey reloadedPvk;

    pvk.encrypt(password);
    pvk.save(outPath);
    reloadedPvk.load(outPath);
    reloadedPvk.decrypt(password);

    EXPECT_EQ(reloadedPvk.getKeyData(), getDummyRsa2Blob());
}

TEST_F(Given_PvkKey, When_LoadEncryptedPvk_ThrowsOnWrongPassword)
{
    std::string outPath = (std::filesystem::temp_directory_path() / "temp_encrypted2.pvk").string();
    registerTemporaryFile(outPath);
    std::string password = "correct_password";
    ccky::crypto::PvkKey pvk;
    pvk.setKeyData(getDummyRsa2Blob(), 1);
    pvk.encrypt(password);
    pvk.save(outPath);
    ccky::crypto::PvkKey reloadedPvk;
    reloadedPvk.load(outPath);

    EXPECT_THROW(
        reloadedPvk.decrypt("wrong_password"), ccky::crypto::PvkIncorrectPasswordException);
}
