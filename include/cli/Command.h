#ifndef CCKY_COMMAND_H
#define CCKY_COMMAND_H

#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
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
    std::vector<std::string> categories;
    std::string triggersHelpCategory;
    size_t padWidth = 0;
    bool hidden = false;

    // For backward compatibility and ease of definition
    FlagDef(std::string name, FlagType type, std::string description, std::string valueName,
        std::string category, size_t pad = 0, std::string triggersHelp = "", bool hide = false)
        : name(std::move(name)), type(type), description(std::move(description)),
          valueName(std::move(valueName)), categories({std::move(category)}),
          triggersHelpCategory(std::move(triggersHelp)), padWidth(pad), hidden(hide)
    {
    }

    FlagDef(std::string name, FlagType type, std::string description, std::string valueName,
        std::vector<std::string> categories, size_t pad = 0, std::string triggersHelp = "",
        bool hide = false)
        : name(std::move(name)), type(type), description(std::move(description)),
          valueName(std::move(valueName)), categories(std::move(categories)),
          triggersHelpCategory(std::move(triggersHelp)), padWidth(pad), hidden(hide)
    {
    }
};

struct UsageBehavior
{
    bool useDashPrefix = false;
    bool noCategoryBlankLines = false;
    bool noInitialBlankLine = false;
    bool noCategoryHeaders = false;
    bool dashSeparator = false;
    bool descriptionAfterFlags = false;
    size_t basePadWidth = 12;
    size_t flagPrefixSpaces = 1;
    size_t alignValueAtCol = 0; // 0 means default/no special alignment, 7 means align at column 7
    bool autoAlignDescriptions = true;
};

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
    UsageBehavior behavior = UsageBehavior{};
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

    int execute(const ParsedArgs& args);

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
