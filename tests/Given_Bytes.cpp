#include <cstdint>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/Bytes.h"

class Given_Bytes : public CckyTest
{
};

TEST_F(Given_Bytes, When_ReadU16LE_ReturnsLittleEndianValue)
{
    uint8_t data[2] = {0x34, 0x12};

    uint16_t val = ccky::crypto::Bytes::readU16LE(data);

    EXPECT_EQ(val, 0x1234);
}

TEST_F(Given_Bytes, When_ReadU32LE_ReturnsLittleEndianValue)
{
    uint8_t data[4] = {0x78, 0x56, 0x34, 0x12};

    uint32_t val = ccky::crypto::Bytes::readU32LE(data);

    EXPECT_EQ(val, 0x12345678U);
}

TEST_F(Given_Bytes, When_ReadU64LE_ReturnsLittleEndianValue)
{
    uint8_t data[8] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};

    uint64_t val = ccky::crypto::Bytes::readU64LE(data);

    EXPECT_EQ(val, 0x0123456789ABCDEFULL);
}

TEST_F(Given_Bytes, When_WriteU16LE_WritesLittleEndianBytes)
{
    uint16_t val = 0xBEEF;
    uint8_t buffer[2] = {0, 0};

    ccky::crypto::Bytes::writeU16LE(val, buffer);

    EXPECT_EQ(buffer[0], 0xEF);
    EXPECT_EQ(buffer[1], 0xBE);
}

TEST_F(Given_Bytes, When_WriteU32LE_WritesLittleEndianBytes)
{
    uint32_t val = 0xDEADBEEFU;
    uint8_t buffer[4] = {0, 0, 0, 0};

    ccky::crypto::Bytes::writeU32LE(val, buffer);

    EXPECT_EQ(buffer[0], 0xEF);
    EXPECT_EQ(buffer[1], 0xBE);
    EXPECT_EQ(buffer[2], 0xAD);
    EXPECT_EQ(buffer[3], 0xDE);
}

TEST_F(Given_Bytes, When_WriteU64LE_WritesLittleEndianBytes)
{
    uint64_t val = 0x0102030405060708ULL;
    uint8_t buffer[8] = {0};

    ccky::crypto::Bytes::writeU64LE(val, buffer);

    EXPECT_EQ(buffer[0], 0x08);
    EXPECT_EQ(buffer[1], 0x07);
    EXPECT_EQ(buffer[2], 0x06);
    EXPECT_EQ(buffer[3], 0x05);
    EXPECT_EQ(buffer[4], 0x04);
    EXPECT_EQ(buffer[5], 0x03);
    EXPECT_EQ(buffer[6], 0x02);
    EXPECT_EQ(buffer[7], 0x01);
}

TEST_F(Given_Bytes, When_AppendU16LE_AppendsLittleEndianBytesToVector)
{
    std::vector<uint8_t> buffer = {0xAA};
    uint16_t val = 0x2211;

    ccky::crypto::Bytes::appendU16LE(buffer, val);

    EXPECT_EQ(buffer.size(), 3U);
    EXPECT_EQ(buffer[0], 0xAA);
    EXPECT_EQ(buffer[1], 0x11);
    EXPECT_EQ(buffer[2], 0x22);
}

TEST_F(Given_Bytes, When_AppendU32LE_AppendsLittleEndianBytesToVector)
{
    std::vector<uint8_t> buffer = {0xBB};
    uint32_t val = 0x44332211U;

    ccky::crypto::Bytes::appendU32LE(buffer, val);

    EXPECT_EQ(buffer.size(), 5U);
    EXPECT_EQ(buffer[0], 0xBB);
    EXPECT_EQ(buffer[1], 0x11);
    EXPECT_EQ(buffer[2], 0x22);
    EXPECT_EQ(buffer[3], 0x33);
    EXPECT_EQ(buffer[4], 0x44);
}

TEST_F(Given_Bytes, When_AppendU64LE_AppendsLittleEndianBytesToVector)
{
    std::vector<uint8_t> buffer = {0xCC};
    uint64_t val = 0x8877665544332211ULL;

    ccky::crypto::Bytes::appendU64LE(buffer, val);

    EXPECT_EQ(buffer.size(), 9U);
    EXPECT_EQ(buffer[0], 0xCC);
    EXPECT_EQ(buffer[1], 0x11);
    EXPECT_EQ(buffer[2], 0x22);
    EXPECT_EQ(buffer[3], 0x33);
    EXPECT_EQ(buffer[4], 0x44);
    EXPECT_EQ(buffer[5], 0x55);
    EXPECT_EQ(buffer[6], 0x66);
    EXPECT_EQ(buffer[7], 0x77);
    EXPECT_EQ(buffer[8], 0x88);
}

TEST_F(Given_Bytes, When_StreamExtractU16LE_ReadsLittleEndianBytes)
{
    std::stringstream ss(std::string("\x34\x12", 2));
    uint16_t val = 0;

    ss >> ccky::crypto::Bytes::U16LE(val);

    EXPECT_EQ(val, 0x1234);
}

TEST_F(Given_Bytes, When_StreamExtractU32LE_ReadsLittleEndianBytes)
{
    std::stringstream ss(std::string("\x78\x56\x34\x12", 4));
    uint32_t val = 0;

    ss >> ccky::crypto::Bytes::U32LE(val);

    EXPECT_EQ(val, 0x12345678U);
}

TEST_F(Given_Bytes, When_StreamExtractU64LE_ReadsLittleEndianBytes)
{
    std::stringstream ss(std::string("\xEF\xCD\xAB\x89\x67\x45\x23\x01", 8));
    uint64_t val = 0;

    ss >> ccky::crypto::Bytes::U64LE(val);

    EXPECT_EQ(val, 0x0123456789ABCDEFULL);
}

TEST_F(Given_Bytes, When_StreamInsertU16LE_WritesLittleEndianBytes)
{
    std::stringstream ss;
    uint16_t val = 0xBEEF;

    ss << ccky::crypto::Bytes::U16LE(val);

    std::string out = ss.str();
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(static_cast<uint8_t>(out[0]), 0xEF);
    EXPECT_EQ(static_cast<uint8_t>(out[1]), 0xBE);
}

TEST_F(Given_Bytes, When_StreamInsertU32LE_WritesLittleEndianBytes)
{
    std::stringstream ss;
    uint32_t val = 0xDEADBEEFU;

    ss << ccky::crypto::Bytes::U32LE(val);

    std::string out = ss.str();
    EXPECT_EQ(out.size(), 4U);
    EXPECT_EQ(static_cast<uint8_t>(out[0]), 0xEF);
    EXPECT_EQ(static_cast<uint8_t>(out[1]), 0xBE);
    EXPECT_EQ(static_cast<uint8_t>(out[2]), 0xAD);
    EXPECT_EQ(static_cast<uint8_t>(out[3]), 0xDE);
}

TEST_F(Given_Bytes, When_StreamInsertU64LE_WritesLittleEndianBytes)
{
    std::stringstream ss;
    uint64_t val = 0x0102030405060708ULL;

    ss << ccky::crypto::Bytes::U64LE(val);

    std::string out = ss.str();
    EXPECT_EQ(out.size(), 8U);
    EXPECT_EQ(static_cast<uint8_t>(out[0]), 0x08);
    EXPECT_EQ(static_cast<uint8_t>(out[1]), 0x07);
    EXPECT_EQ(static_cast<uint8_t>(out[2]), 0x06);
    EXPECT_EQ(static_cast<uint8_t>(out[3]), 0x05);
    EXPECT_EQ(static_cast<uint8_t>(out[4]), 0x04);
    EXPECT_EQ(static_cast<uint8_t>(out[5]), 0x03);
    EXPECT_EQ(static_cast<uint8_t>(out[6]), 0x02);
    EXPECT_EQ(static_cast<uint8_t>(out[7]), 0x01);
}
