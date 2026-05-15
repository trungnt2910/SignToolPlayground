#ifndef CCKY_COMMAND_H
#define CCKY_COMMAND_H

#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "crypto/CckyException.h"

namespace ccky
{
namespace cli
{

enum class FlagType
{
    Boolean,
    Value,
    MultiValue
};

struct FlagDef
{
    std::string name; // without leading / or -
    FlagType type;
    std::string description;
    std::string valueName;
    std::string category;
    size_t padWidth = 0;
};

enum class UsageBehaviorFlags : uint32_t
{
    None = 0,
    UseDashPrefix = 1 << 0,        // ' -' prefix instead of '/'
    WideBasePad = 1 << 1,          // basePadWidth 20 instead of 12
    NoCategoryBlankLines = 1 << 2, // no ss << "\n" between categories
    AlignValueAtCol7 = 1 << 3,     // align valueName at col 7
    NoInitialBlankLine = 1 << 4    // no initial ss << "\n" after usageHeader
};

inline UsageBehaviorFlags operator|(UsageBehaviorFlags a, UsageBehaviorFlags b)
{
    return static_cast<UsageBehaviorFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline UsageBehaviorFlags operator&(UsageBehaviorFlags a, UsageBehaviorFlags b)
{
    return static_cast<UsageBehaviorFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

struct SubcommandInfo
{
    std::string name;
    std::string summary;
};

struct UsageInfo
{
    std::string usageHeader;
    std::string description;
    std::vector<SubcommandInfo> subcommands;
    std::vector<FlagDef> flags;
    UsageBehaviorFlags behavior = UsageBehaviorFlags::None;
};

struct ParsedArgs
{
    std::string command;
    std::string subcommand;
    std::map<std::string, std::vector<std::string>> flags;
    std::vector<std::string> positional;
    std::vector<std::map<std::string, std::vector<std::string>>> positionalFlags;

    bool hasFlag(const std::string& flag) const
    {
        std::string lower = flag;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return flags.find(lower) != flags.end();
    }

    std::string getFlagValue(const std::string& flag, const std::string& defaultValue = "") const
    {
        std::string lower = flag;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = flags.find(lower);
        if (it != flags.end() && !it->second.empty())
        {
            return it->second.front();
        }
        return defaultValue;
    }

    std::vector<std::string> getFlagValues(const std::string& flag) const
    {
        std::string lower = flag;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = flags.find(lower);
        if (it != flags.end())
        {
            return it->second;
        }
        return {};
    }
};

class CommandRegistry;

class Command
{
  public:
    explicit Command(
        std::istream& in = std::cin, std::ostream& out = std::cout, std::ostream& err = std::cerr)
        : m_in(in), m_out(out), m_err(err), m_registry(nullptr)
    {
    }
    virtual ~Command() = default;

    void setRegistry(const CommandRegistry* registry) { m_registry = registry; }
    virtual void registerUsage(CommandRegistry* registry) = 0;

    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual bool hasSubcommands() const = 0;
    virtual bool isSubcommand(const std::string& arg) const = 0;
    virtual std::vector<FlagDef> getFlagDefs(const std::string& subcommand) const = 0;

    int execute(const ParsedArgs& args)
    {
        try
        {
            return executeImpl(args);
        }
        catch (const crypto::CckyException& e)
        {
            displayError(e);
            if (e.shouldPrintHelp())
            {
                printHelp();
            }
            return 1;
        }
        catch (const std::exception& e)
        {
            displayError(e);
            return 1;
        }
        catch (...)
        {
            displayError("Unknown error occurred.");
            return 1;
        }
    }

    virtual void printHelp() = 0;

  protected:
    virtual int executeImpl(const ParsedArgs& args) = 0;
    virtual void displayError(const std::exception& e) = 0;
    virtual void displayError(const std::string& msg) = 0;

    std::istream& m_in;
    std::ostream& m_out;
    std::ostream& m_err;
    const CommandRegistry* m_registry;
};

} // namespace cli
} // namespace ccky

#endif // CCKY_COMMAND_H
