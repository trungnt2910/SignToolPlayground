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
    // Set aiKeyAlg to CALG_RSA_SIGN (0x00002400)
    blob[4] = 0x00;
    blob[5] = 0x24;
    blob[6] = 0x00;
    blob[7] = 0x00;
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
    pvk.setKeyData(getDummyRsa2Blob(), ccky::crypto::PvkKeySpec::KeyExchange);
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
    pvk.setKeyData(getDummyRsa2Blob(), ccky::crypto::PvkKeySpec::KeyExchange);
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
    pvk.setKeyData(getDummyRsa2Blob(), ccky::crypto::PvkKeySpec::KeyExchange);
    pvk.encrypt(password);
    pvk.save(outPath);
    ccky::crypto::PvkKey reloadedPvk;
    reloadedPvk.load(outPath);

    EXPECT_THROW(
        reloadedPvk.decrypt("wrong_password"), ccky::crypto::PvkIncorrectPasswordException);
}

TEST_F(Given_PvkKey, When_LoadWindowsEncryptedPvk_Succeeds)
{
    std::string pvkPath = getTestDataPath("tests/data/1234.pvk");
    ccky::crypto::PvkKey pvk;

    pvk.load(pvkPath);
    pvk.decrypt("1234");

    EXPECT_FALSE(pvk.getKeyData().empty());
}

TEST_F(Given_PvkKey, When_ReencryptPvk_MatchesOriginal)
{
    std::string pvkPath = getTestDataPath("tests/data/1234.pvk");
    std::string outPath =
        (std::filesystem::temp_directory_path() / "temp_reencrypted.pvk").string();
    registerTemporaryFile(outPath);
    ccky::crypto::PvkKey pvk;
    pvk.load(pvkPath);
    std::vector<uint8_t> salt = pvk.getSalt();
    pvk.decrypt("1234");

    pvk.encrypt("1234", salt);
    pvk.save(outPath);

    expectFilesEqual(pvkPath, outPath);
}

TEST_F(Given_PvkKey, When_LoadUnencryptedPvkWithBadVersion_ThrowsBadProviderVersion)
{
    std::string outPath =
        (std::filesystem::temp_directory_path() / "temp_bad_version_unencrypted.pvk").string();
    registerTemporaryFile(outPath);
    ccky::crypto::PvkKey pvk;
    std::vector<uint8_t> badBlob(8, 0);
    pvk.setKeyData(badBlob, ccky::crypto::PvkKeySpec::KeyExchange);
    pvk.encrypt("");
    pvk.save(outPath);
    ccky::crypto::PvkKey reloadedPvk;

    EXPECT_THROW(reloadedPvk.load(outPath), ccky::crypto::PvkBadProviderVersionException);
}

TEST_F(Given_PvkKey, When_LoadEncryptedPvkWithBadVersion_ThrowsBadProviderVersion)
{
    std::string outPath =
        (std::filesystem::temp_directory_path() / "temp_bad_version_encrypted.pvk").string();
    registerTemporaryFile(outPath);
    ccky::crypto::PvkKey pvk;
    std::vector<uint8_t> badBlob(8, 0);
    pvk.setKeyData(badBlob, ccky::crypto::PvkKeySpec::KeyExchange);
    pvk.encrypt("password");
    pvk.save(outPath);
    ccky::crypto::PvkKey reloadedPvk;

    EXPECT_THROW(reloadedPvk.load(outPath), ccky::crypto::PvkBadProviderVersionException);
}
