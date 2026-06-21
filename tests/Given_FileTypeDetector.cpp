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
    std::filesystem::copy_file(
        origPePath, peDat, std::filesystem::copy_options::overwrite_existing);
    EXPECT_EQ(
        ccky::crypto::FileTypeDetector::detectFileType(peDat), ccky::crypto::StoreType::PeFile);
    std::filesystem::remove(peDat);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithPfx_DetectsPfxFile)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    EXPECT_EQ(
        ccky::crypto::FileTypeDetector::detectFileType(pfxPath), ccky::crypto::StoreType::PfxFile);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithCer_DetectsCerFile)
{
    std::string cerPath = getTestDataPath("tests/data/lxmonika.cer");
    EXPECT_EQ(
        ccky::crypto::FileTypeDetector::detectFileType(cerPath), ccky::crypto::StoreType::CerFile);
}

TEST_F(Given_FileTypeDetector, When_DetectFileTypeWithAppxDat_DetectsAppxFile)
{
    std::string origAppxPath = getTestDataPath("tests/data/test.appx");
    std::string appxDat = "detect_test_appx.dat";
    std::filesystem::copy_file(
        origAppxPath, appxDat, std::filesystem::copy_options::overwrite_existing);
    EXPECT_EQ(
        ccky::crypto::FileTypeDetector::detectFileType(appxDat), ccky::crypto::StoreType::AppxFile);
    std::filesystem::remove(appxDat);
}
