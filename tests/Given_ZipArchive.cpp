#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#ifndef _WIN32
#include "crypto/openssl/ZipArchive.h"
#endif

class Given_ZipArchive : public CckyTest
{
};

TEST_F(Given_ZipArchive, When_LoadZip64Appx_LoadsEntriesCorrectly)
{
#ifdef _WIN32
    GTEST_SKIP() << "ZipArchive is only built with OpenSSL backend.";
#else
    std::string srcPath = getTestDataPath("tests/data/ccky.appx");

    ccky::crypto::ZipArchive archive(srcPath);

    EXPECT_GT(archive.getEntryOrder().size(), 10);
    EXPECT_TRUE(archive.hasEntry("MainWindowView.xaml"));
    EXPECT_TRUE(archive.hasEntry("CoreAppMinGW.exe"));
#endif
}

TEST_F(Given_ZipArchive, When_LoadAndSaveZip64Appx_PreservesEntryFlagsAndContent)
{
#ifdef _WIN32
    GTEST_SKIP() << "ZipArchive is only built with OpenSSL backend.";
#else
    std::string srcPath = getTestDataPath("tests/data/ccky.appx");
    std::string outPath = "temp_ziparchive_test.appx";
    registerTemporaryFile(outPath);
    std::filesystem::copy_file(srcPath, outPath, std::filesystem::copy_options::overwrite_existing);
    std::vector<uint8_t> dummyXml = {'<', 'x', 'm', 'l', '>'};

    {
        ccky::crypto::ZipArchive archive(outPath);
        archive.setEntryContent("[Content_Types].xml", dummyXml, false);
        archive.save(outPath);
    }
    ccky::crypto::ZipArchive reloaded(outPath);

    EXPECT_TRUE(reloaded.hasEntry("MainWindowView.xaml"));
    EXPECT_TRUE(reloaded.hasEntry("CoreAppMinGW.exe"));
    EXPECT_TRUE(reloaded.hasEntry("[Content_Types].xml"));
    EXPECT_EQ(reloaded.getEntry("[Content_Types].xml")->uncompSize, 5);
    EXPECT_EQ(reloaded.getEntry("[Content_Types].xml")->gpFlags &
                  ccky::crypto::ZipGeneralPurposeFlags::DataDescriptor,
        0);
#endif
}

TEST_F(Given_ZipArchive, When_LoadZip64Appx_EntryHasDataDescriptorFlag)
{
#ifdef _WIN32
    GTEST_SKIP() << "ZipArchive is only built with OpenSSL backend.";
#else
    std::string srcPath = getTestDataPath("tests/data/ccky.appx");

    ccky::crypto::ZipArchive archive(srcPath);
    const auto* origEntry = archive.getEntry("[Content_Types].xml");

    ASSERT_NE(origEntry, nullptr);
    EXPECT_NE(origEntry->gpFlags & ccky::crypto::ZipGeneralPurposeFlags::DataDescriptor, 0);
#endif
}

TEST_F(Given_ZipArchive, When_SetEntryContent_ClearsDataDescriptorFlag)
{
#ifdef _WIN32
    GTEST_SKIP() << "ZipArchive is only built with OpenSSL backend.";
#else
    std::string srcPath = getTestDataPath("tests/data/ccky.appx");
    std::string outPath = "temp_gpflags_test.appx";
    registerTemporaryFile(outPath);
    std::filesystem::copy_file(srcPath, outPath, std::filesystem::copy_options::overwrite_existing);
    ccky::crypto::ZipArchive archive(outPath);
    std::vector<uint8_t> newData = {'<', 'n', 'e', 'w', '>'};

    archive.setEntryContent("[Content_Types].xml", newData, false);
    const auto* modEntry = archive.getEntry("[Content_Types].xml");

    ASSERT_NE(modEntry, nullptr);
    EXPECT_EQ(modEntry->gpFlags & ccky::crypto::ZipGeneralPurposeFlags::DataDescriptor, 0);
#endif
}

TEST_F(Given_ZipArchive, When_SerializeCentralDirHeaderWithZip64_OutputsSentinelMasks)
{
#ifdef _WIN32
    GTEST_SKIP() << "ZipArchive is only built with OpenSSL backend.";
#else
    ccky::crypto::ZipEntry entry;
    entry.uncompSize = 5000;
    entry.compSize = 2000;
    entry.extra = {0x01, 0x00, 0x18, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0};
    std::vector<uint8_t> buf;

    ccky::crypto::ZipSerializer::serializeCentralDirHeader(buf, entry, "Dummy.txt", 1234);

    ASSERT_GE(buf.size(), 46);
    uint32_t compSize = 0;
    uint32_t uncompSize = 0;
    uint32_t offset = 0;
    std::memcpy(&compSize, &buf[20], 4);
    std::memcpy(&uncompSize, &buf[24], 4);
    std::memcpy(&offset, &buf[42], 4);
    EXPECT_EQ(compSize, ccky::crypto::ZipConstants::Zip64HeaderMask);
    EXPECT_EQ(uncompSize, ccky::crypto::ZipConstants::Zip64HeaderMask);
    EXPECT_EQ(offset, ccky::crypto::ZipConstants::Zip64HeaderMask);
#endif
}
