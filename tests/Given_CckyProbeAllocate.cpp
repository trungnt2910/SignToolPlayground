#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "crypto/CckyProbeAllocate.h"

using namespace ccky::crypto;

namespace
{

int mockApiWithSizeRef(uint8_t* buf, int* size)
{
    if (buf == nullptr)
    {
        *size = 5;
        return 1;
    }
    std::memcpy(buf, "Hello", 5);
    *size = 5;
    return 1;
}

int mockApiWithReturnSize(char* buf, int size)
{
    if (buf == nullptr || size == 0)
    {
        return 5;
    }
    std::memcpy(buf, "World", 5);
    return 5;
}

int mockApiFailure(uint8_t* buf, int* size) { return 0; }

int mockApiMultiByte(wchar_t* buf, int* cbSize)
{
    const wchar_t msg[] = L"Test";
    const int bytes = sizeof(msg);
    if (buf == nullptr)
    {
        *cbSize = bytes;
        return 1;
    }
    std::memcpy(buf, msg, bytes);
    *cbSize = bytes;
    return 1;
}

int mockApiElementSizeRef(wchar_t* buf, int* cchSize)
{
    if (buf == nullptr)
    {
        *cchSize = 5;
        return 1;
    }
    std::memcpy(buf, L"Test", sizeof(L"Test"));
    *cchSize = 5;
    return 1;
}

int mockApiFetchFailure(uint8_t* buf, int* size)
{
    if (buf == nullptr)
    {
        *size = 10;
        return 1;
    }
    return 0;
}

} // namespace

TEST(Given_CckyProbeAllocate, When_ProbeSizeRefProvided_AllocatesAndPopulatesBuffer)
{
    std::vector<uint8_t> buffer;

    int result =
        CckyProbeAllocate<mockApiWithSizeRef>(CckyProbeBuffer(buffer), CckyProbeBytesRef<int>());

    EXPECT_EQ(result, 1);
    EXPECT_EQ(buffer.size(), 5u);
    EXPECT_EQ(std::string(buffer.begin(), buffer.end()), "Hello");
}

TEST(Given_CckyProbeAllocate, When_ReturnSizeUsed_AllocatesAndPopulatesBuffer)
{
    std::string buffer;

    int result = CckyProbeAllocate<mockApiWithReturnSize, CckyProbeReturnPositive{}>(
        CckyProbeBuffer(buffer), CckyProbeSize{});

    EXPECT_EQ(result, 5);
    EXPECT_EQ(buffer.size(), 5u);
    EXPECT_EQ(buffer, "World");
}

TEST(Given_CckyProbeAllocate, When_ProbeFails_ReturnsFailureWithoutAllocating)
{
    std::vector<uint8_t> buffer;

    int result =
        CckyProbeAllocate<mockApiFailure>(CckyProbeBuffer(buffer), CckyProbeBytesRef<int>());

    EXPECT_EQ(result, 0);
    EXPECT_TRUE(buffer.empty());
}

TEST(Given_CckyProbeAllocate, When_MultiByteContainerUsed_AllocatesCorrectElementCount)
{
    std::wstring buffer;

    int result =
        CckyProbeAllocate<mockApiMultiByte>(CckyProbeBuffer(buffer), CckyProbeBytesRef<int>());

    EXPECT_EQ(result, 1);
    EXPECT_EQ(buffer.size(), 5u);
    EXPECT_STREQ(buffer.c_str(), L"Test");
}

TEST(Given_CckyProbeAllocate, When_ProbeSizeRefProvidedForElements_AllocatesCorrectElementCount)
{
    std::wstring buffer;

    int result =
        CckyProbeAllocate<mockApiElementSizeRef>(CckyProbeBuffer(buffer), CckyProbeSizeRef<int>());

    EXPECT_EQ(result, 1);
    EXPECT_EQ(buffer.size(), 5u);
    EXPECT_STREQ(buffer.c_str(), L"Test");
}

TEST(Given_CckyProbeAllocate, When_FetchPassFails_ClearsBufferAndReturnsFailure)
{
    std::vector<uint8_t> buffer;

    int result =
        CckyProbeAllocate<mockApiFetchFailure>(CckyProbeBuffer(buffer), CckyProbeBytesRef<int>());

    EXPECT_EQ(result, 0);
    EXPECT_TRUE(buffer.empty());
}
