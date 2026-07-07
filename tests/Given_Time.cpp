#include <chrono>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/Time.h"

class Given_Time : public CckyTest
{
};

TEST_F(Given_Time, When_Jan31PlusOneMonthInUtcMode_ReturnsExactFeb28)
{
    ccky::crypto::Time::setFormatUTC(true);
    std::chrono::sys_days startDays =
        std::chrono::year{2026} / std::chrono::January / std::chrono::day{31};
    std::chrono::system_clock::time_point startTime = startDays;
    std::chrono::sys_days expectedDays =
        std::chrono::year{2026} / std::chrono::February / std::chrono::day{28};
    std::chrono::system_clock::time_point expectedTime = expectedDays;

    auto actualTime = ccky::crypto::Time::addMonths(startTime, 1);

    EXPECT_EQ(actualTime, expectedTime);
}

TEST_F(Given_Time, When_Jan31PlusOneMonthInLocalMode_ReturnsWithin24HoursOfFeb28Gmt)
{
    ccky::crypto::Time::setFormatUTC(false);
    std::chrono::sys_days startDays =
        std::chrono::year{2026} / std::chrono::January / std::chrono::day{31};
    std::chrono::system_clock::time_point startTime = startDays;
    std::chrono::sys_days targetGmtDays =
        std::chrono::year{2026} / std::chrono::February / std::chrono::day{28};
    std::chrono::system_clock::time_point targetGmtTime = targetGmtDays;

    auto actualTime = ccky::crypto::Time::addMonths(startTime, 1);

    auto diff =
        actualTime > targetGmtTime ? actualTime - targetGmtTime : targetGmtTime - actualTime;
    EXPECT_LE(diff, std::chrono::hours{24});
}
