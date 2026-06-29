#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/FileTypeDetector.h"

class Given_FileTypeDetector : public CckyTest
{
};

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithPeDat_DetectsPeFile)
{
    std::string origPePath = getTestDataPath("tests/data/test.exe");
    std::string peDat = "detect_test_pe.dat";
    registerTemporaryFile(peDat);
    std::filesystem::copy_file(
        origPePath, peDat, std::filesystem::copy_options::overwrite_existing);

    auto type = ccky::crypto::FileTypeDetector::detectFileType(peDat);

    EXPECT_EQ(type, ccky::crypto::StoreType::PeFile);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithPfx_DetectsPfxFile)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");

    auto type = ccky::crypto::FileTypeDetector::detectFileType(pfxPath);

    EXPECT_EQ(type, ccky::crypto::StoreType::PfxFile);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithCer_DetectsCerFile)
{
    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");

    auto type = ccky::crypto::FileTypeDetector::detectFileType(cerPath);

    EXPECT_EQ(type, ccky::crypto::StoreType::CerFile);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithAppxDat_DetectsAppxFile)
{
    std::string origAppxPath = getTestDataPath("tests/data/test.appx");
    std::string appxDat = "detect_test_appx.dat";
    registerTemporaryFile(appxDat);
    std::filesystem::copy_file(
        origAppxPath, appxDat, std::filesystem::copy_options::overwrite_existing);

    auto type = ccky::crypto::FileTypeDetector::detectFileType(appxDat);

    EXPECT_EQ(type, ccky::crypto::StoreType::AppxFile);
}
