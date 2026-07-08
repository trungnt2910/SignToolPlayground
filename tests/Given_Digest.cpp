#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/CryptoFactory.h"
#include "crypto/Digest.h"

using namespace ccky::crypto;

class Given_Digest : public CckyTest
{
};

TEST_F(Given_Digest, When_GetDigestFromName_Sha256_ReturnsValidDigest)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");

    ASSERT_NE(digest, nullptr);
    EXPECT_EQ(digest->getName(), "sha256");
    EXPECT_EQ(digest->getOid(), "2.16.840.1.101.3.4.2.1");
}

TEST_F(Given_Digest, When_GetDigestFromName_Sha256Upper_ReturnsValidDigest)
{
    auto digest = CryptoFactory::getDigestFromName("SHA256");

    ASSERT_NE(digest, nullptr);
    EXPECT_EQ(digest->getName(), "sha256");
    EXPECT_EQ(digest->getOid(), "2.16.840.1.101.3.4.2.1");
}

TEST_F(Given_Digest, When_GetDigestFromName_Sha1_ReturnsValidDigest)
{
    auto digest = CryptoFactory::getDigestFromName("sha1");

    ASSERT_NE(digest, nullptr);
    EXPECT_EQ(digest->getName(), "sha1");
    EXPECT_EQ(digest->getOid(), "1.3.14.3.2.26");
}

TEST_F(Given_Digest, When_GetDigestFromOid_Sha256Oid_ReturnsValidDigest)
{
    auto digest = CryptoFactory::getDigestFromOid("2.16.840.1.101.3.4.2.1");

    ASSERT_NE(digest, nullptr);
    EXPECT_EQ(digest->getName(), "sha256");
    EXPECT_EQ(digest->getOid(), "2.16.840.1.101.3.4.2.1");
}

TEST_F(Given_Digest, When_GetDigestFromOid_Sha1Oid_ReturnsValidDigest)
{
    auto digest = CryptoFactory::getDigestFromOid("1.3.14.3.2.26");

    ASSERT_NE(digest, nullptr);
    EXPECT_EQ(digest->getName(), "sha1");
    EXPECT_EQ(digest->getOid(), "1.3.14.3.2.26");
}

TEST_F(Given_Digest, When_GetDigestWithInvalidName_ReturnsNullptr)
{
    auto digest = CryptoFactory::getDigestFromName("invalid-digest-name");

    EXPECT_EQ(digest, nullptr);
}

TEST_F(Given_Digest, When_GetDigestWithInvalidOid_ReturnsNullptr)
{
    auto digest = CryptoFactory::getDigestFromOid("1.2.3.4.5.6.7.8.9");

    EXPECT_EQ(digest, nullptr);
}

TEST_F(Given_Digest, When_CalculateHashData_Sha256_ReturnsExpectedHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};

    auto hash = digest->calculateHash(data);
    auto hashStr = digest->calculateHashString(data);

    std::vector<uint8_t> expectedBytes = {0x18, 0x5F, 0x8D, 0xB3, 0x22, 0x71, 0xFE, 0x25, 0xF5,
        0x61, 0xA6, 0xFC, 0x93, 0x8B, 0x2E, 0x26, 0x43, 0x06, 0xEC, 0x30, 0x4E, 0xDA, 0x51, 0x80,
        0x07, 0xD1, 0x76, 0x48, 0x26, 0x38, 0x19, 0x69};
    EXPECT_EQ(hash, expectedBytes);
    EXPECT_EQ(hashStr, "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969");
}

TEST_F(Given_Digest, When_CalculateHashData_Sha1_ReturnsExpectedHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha1");
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};

    auto hash = digest->calculateHash(data);
    auto hashStr = digest->calculateHashString(data);

    std::vector<uint8_t> expectedBytes = {0xF7, 0xFF, 0x9E, 0x8B, 0x7B, 0xB2, 0xE0, 0x9B, 0x70,
        0x93, 0x5A, 0x5D, 0x78, 0x5E, 0x0C, 0xC5, 0xD9, 0xD0, 0xAB, 0xF0};
    EXPECT_EQ(hash, expectedBytes);
    EXPECT_EQ(hashStr, "F7FF9E8B7BB2E09B70935A5D785E0CC5D9D0ABF0");
}

TEST_F(Given_Digest, When_CalculateHashFile_Sha256_ReturnsExpectedHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");
    std::string testFilePath = "test_digest_temp_sha256.txt";
    registerTemporaryFile(testFilePath);
    {
        std::ofstream out(testFilePath, std::ios::binary);
        out << "Hello";
    }

    auto hash = digest->calculateHash(testFilePath);
    auto hashStr = digest->calculateHashString(testFilePath);

    std::vector<uint8_t> expectedBytes = {0x18, 0x5F, 0x8D, 0xB3, 0x22, 0x71, 0xFE, 0x25, 0xF5,
        0x61, 0xA6, 0xFC, 0x93, 0x8B, 0x2E, 0x26, 0x43, 0x06, 0xEC, 0x30, 0x4E, 0xDA, 0x51, 0x80,
        0x07, 0xD1, 0x76, 0x48, 0x26, 0x38, 0x19, 0x69};
    EXPECT_EQ(hash, expectedBytes);
    EXPECT_EQ(hashStr, "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969");
}

TEST_F(Given_Digest, When_CalculateHashFileFromTestExe_Sha256_ReturnsExpectedHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");
    std::string path = getTestDataPath("tests/data/test.exe");

    std::string hash = digest->calculateHashString(path);

    EXPECT_EQ(hash, "592C1A2FA449F9617FF60AB3EDC3776ED5507A45616237EF472DCA839C0356CF");
}

TEST_F(Given_Digest, When_StreamHash_ReturnsIntermediateAndFinalExpectedHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");
    auto stream = digest->createStream();
    std::vector<uint8_t> chunk1 = {'H', 'e'};
    std::vector<uint8_t> chunk2 = {'l', 'l', 'o'};

    stream->update(chunk1);
    auto intermediateHashStr = stream->calculateHashString();
    stream->update(chunk2);
    auto finalHashStr = stream->calculateHashString();

    EXPECT_EQ(
        intermediateHashStr, "30EFDFB52FF67F80DAB7CB89DCFE0EEC8412966CFE58324993674B4616D6BD11");
    EXPECT_EQ(finalHashStr, "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969");
}

TEST_F(Given_Digest, When_StreamHashOperatorShift_UpdatesHash)
{
    auto digest = CryptoFactory::getDigestFromName("sha256");
    auto stream = digest->createStream();
    std::vector<uint8_t> chunk1 = {'H', 'e'};
    std::vector<uint8_t> chunk2 = {'l', 'l', 'o'};

    (*stream) << chunk1 << chunk2;
    auto finalHashStr = stream->calculateHashString();

    EXPECT_EQ(finalHashStr, "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969");
}
