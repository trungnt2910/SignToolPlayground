#include "cli/CommandRegistry.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace ccky
{
namespace cli
{

void CommandRegistry::registerCommand(std::shared_ptr<Command> command)
{
    if (command)
    {
        command->setRegistry(this);
        command->registerUsage(this);
        std::string lower = command->getName();
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        m_commands[lower] = command;
    }
}

std::shared_ptr<Command> CommandRegistry::getCommand(const std::string& name) const
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    auto it = m_commands.find(lower);
    if (it != m_commands.end())
    {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<Command>> CommandRegistry::getAllCommands() const
{
    std::vector<std::shared_ptr<Command>> list;
    for (const auto& pair : m_commands)
    {
        list.push_back(pair.second);
    }
    return list;
}

void CommandRegistry::registerCommandUsage(const std::string& command,
    const std::string& subcommand, const std::string& usageHeader,
    const std::string& cmdDescription, const std::vector<SubcommandInfo>& subcommands,
    const std::vector<FlagDef>& flags, UsageBehaviorFlags behavior)
{
    std::string lowerCmd = command;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);
    std::string lowerSub = subcommand;
    std::transform(lowerSub.begin(), lowerSub.end(), lowerSub.begin(), ::tolower);
    m_usageRegistry[{lowerCmd, lowerSub}] = {
        usageHeader, cmdDescription, subcommands, flags, behavior};
}

std::string CommandRegistry::getUsage(
    const std::string& command, const std::string& subcommand) const
{
    std::string lowerCmd = command;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);
    std::string lowerSub = subcommand;
    std::transform(lowerSub.begin(), lowerSub.end(), lowerSub.begin(), ::tolower);

    auto it = m_usageRegistry.find({lowerCmd, lowerSub});
    if (it == m_usageRegistry.end())
    {
        return "";
    }

    const auto& info = it->second;
    std::stringstream ss;

    bool useDashPrefix = (static_cast<uint32_t>(info.behavior) &
                             static_cast<uint32_t>(UsageBehaviorFlags::UseDashPrefix)) != 0;
    bool wideBasePad = (static_cast<uint32_t>(info.behavior) &
                           static_cast<uint32_t>(UsageBehaviorFlags::WideBasePad)) != 0;
    bool noCatBlankLines =
        (static_cast<uint32_t>(info.behavior) &
            static_cast<uint32_t>(UsageBehaviorFlags::NoCategoryBlankLines)) != 0;
    bool alignCol7 = (static_cast<uint32_t>(info.behavior) &
                         static_cast<uint32_t>(UsageBehaviorFlags::AlignValueAtCol7)) != 0;
    bool noInitBlankLine = (static_cast<uint32_t>(info.behavior) &
                               static_cast<uint32_t>(UsageBehaviorFlags::NoInitialBlankLine)) != 0;

    if (!info.usageHeader.empty())
    {
        ss << info.usageHeader;
        if (info.subcommands.empty() && info.flags.empty() && !info.description.empty())
        {
            ss << "\n" << info.description << "\n";
            return ss.str();
        }
        if (!info.flags.empty() && !noInitBlankLine)
        {
            ss << "\n";
        }
    }

    if (!info.subcommands.empty())
    {
        ss << "\n  Valid commands:\n";
        for (const auto& sub : info.subcommands)
        {
            std::string subPart = "    " + sub.name;
            size_t pad = 15;
            if (subPart.size() < pad)
            {
                subPart += std::string(pad - subPart.size(), ' ');
            }
            subPart += "--  ";

            std::string summary = sub.summary;
            std::string indentStr(pad + 4, ' ');
            size_t pos = 0;
            bool firstLine = true;
            while (pos < summary.size())
            {
                size_t nextNewline = summary.find('\n', pos);
                if (nextNewline == std::string::npos)
                {
                    if (firstLine)
                    {
                        ss << subPart << summary.substr(pos) << "\n";
                    }
                    else
                    {
                        ss << indentStr << summary.substr(pos) << "\n";
                    }
                    break;
                }
                else
                {
                    if (firstLine)
                    {
                        ss << subPart << summary.substr(pos, nextNewline - pos) << "\n";
                    }
                    else
                    {
                        ss << indentStr << summary.substr(pos, nextNewline - pos) << "\n";
                    }
                    pos = nextNewline + 1;
                    firstLine = false;
                }
            }
        }
        ss << "\n                   For help on a specific command, enter \"" << lowerCmd
           << " <command> /?\"\n";
        if (!info.description.empty())
        {
            ss << "\n" << info.description;
        }
        return ss.str();
    }

    if (!info.description.empty())
    {
        ss << info.description << "\n\n";
    }

    std::string prefix = useDashPrefix ? " -" : "/";
    size_t basePadWidth = wideBasePad ? 20 : 12;

    std::vector<std::string> categories;
    std::map<std::string, std::vector<FlagDef>> catMap;
    for (const auto& f : info.flags)
    {
        std::string cat = f.category;
        if (catMap.find(cat) == catMap.end())
        {
            categories.push_back(cat);
        }
        catMap[cat].push_back(f);
    }

    for (size_t cIdx = 0; cIdx < categories.size(); ++cIdx)
    {
        std::string cat = categories[cIdx];
        if (!cat.empty())
        {
            ss << cat << "\n";
        }

        for (const auto& f : catMap[cat])
        {
            size_t pw = (f.padWidth > 0) ? f.padWidth : basePadWidth;
            std::string flagPart = prefix + f.name;
            if (!f.valueName.empty())
            {
                if (alignCol7)
                {
                    size_t targetCol = 7;
                    if (flagPart.size() < targetCol)
                    {
                        flagPart += std::string(targetCol - flagPart.size(), ' ') + f.valueName;
                    }
                    else
                    {
                        flagPart += " " + f.valueName;
                    }
                }
                else
                {
                    flagPart += " " + f.valueName;
                }
            }

            ss << flagPart;
            if (flagPart.size() < pw)
            {
                for (size_t p = flagPart.size(); p < pw; ++p)
                {
                    ss << " ";
                }
            }
            else
            {
                ss << " ";
            }

            ss << f.description << "\n";
        }
        if (!noCatBlankLines && cIdx + 1 < categories.size())
        {
            ss << "\n";
        }
    }

    return ss.str();
}

} // namespace cli
} // namespace ccky
