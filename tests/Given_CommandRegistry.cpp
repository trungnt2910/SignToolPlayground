#include <gtest/gtest.h>

#include "cli/CommandRegistry.h"

TEST(Given_CommandRegistry, When_DefaultBehavior_RendersCorrectly)
{
    ccky::cli::CommandRegistry registry;
    registry.registerCommandUsage("testcmd", "", "Usage: testcmd\n", "Description", {},
        {{"flag1", ccky::cli::FlagType::Boolean, "Flag 1 description", "", "Category 1"}});

    std::string usage = registry.getUsage("testcmd", "");

    std::string expected = "Usage: testcmd\n"
                           "\n"
                           "Description\n"
                           "\n"
                           "Category 1\n"
                           "/flag1      Flag 1 description\n";
    EXPECT_EQ(usage, expected);
}

TEST(Given_CommandRegistry, When_CustomBehavior_RendersCorrectly)
{
    ccky::cli::CommandRegistry registry;
    ccky::cli::UsageBehavior behavior;
    behavior.useDashPrefix = true;
    behavior.noCategoryHeaders = true;
    behavior.flagPrefixSpaces = 8;
    behavior.dashSeparator = true;
    behavior.descriptionAfterFlags = true;
    behavior.basePadWidth = 25;
    registry.registerCommandUsage("testcmd", "", "Usage: testcmd\n", "Description", {},
        {{"flag1", ccky::cli::FlagType::Value, "Flag 1 description", "<val>", "Category 1"}},
        behavior);

    std::string usage = registry.getUsage("testcmd", "");

    std::string expected = "Usage: testcmd\n"
                           "\n"
                           "        -flag1 <val>     - Flag 1 description\n"
                           "\n"
                           "Description\n";
    EXPECT_EQ(usage, expected);
}

TEST(Given_CommandRegistry, When_AlignValueAtCol_RendersCorrectly)
{
    ccky::cli::CommandRegistry registry;
    ccky::cli::UsageBehavior behavior;
    behavior.useDashPrefix = true;
    behavior.alignValueAtCol = 8;
    behavior.basePadWidth = 20;
    registry.registerCommandUsage("testcmd", "", "Usage: testcmd\n", "Description", {},
        {{"f", ccky::cli::FlagType::Value, "Flag description", "<val>", "Category 1"}}, behavior);

    std::string usage = registry.getUsage("testcmd", "");

    std::string expected = "Usage: testcmd\n"
                           "\n"
                           "Description\n"
                           "\n"
                           "Category 1\n"
                           " -f     <val>       Flag description\n";
    EXPECT_EQ(usage, expected);
}

TEST(Given_CommandRegistry, When_FlagPadWidth_RendersCorrectly)
{
    ccky::cli::CommandRegistry registry;
    ccky::cli::UsageBehavior behavior;
    behavior.useDashPrefix = true;
    behavior.basePadWidth = 10;
    registry.registerCommandUsage("testcmd", "", "Usage: testcmd\n", "Description", {},
        {{"flag1", ccky::cli::FlagType::Boolean, "Flag 1 description", "", "Category 1", 15}},
        behavior);

    std::string usage = registry.getUsage("testcmd", "");

    std::string expected = "Usage: testcmd\n"
                           "\n"
                           "Description\n"
                           "\n"
                           "Category 1\n"
                           " -flag1        Flag 1 description\n";
    EXPECT_EQ(usage, expected);
}
