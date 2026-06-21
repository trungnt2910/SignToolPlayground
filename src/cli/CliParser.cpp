#include "cli/CliParser.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>

namespace ccky
{
namespace cli
{

ParsedArgs CliParser::parse(int argc, const char* const argv[], const CommandRegistry& registry)
{
    ParsedArgs args;
    if (argc < 1)
    {
        return args;
    }

    std::string execName = argv[0];
    size_t slash = execName.find_last_of("/\\");
    if (slash != std::string::npos)
    {
        execName = execName.substr(slash + 1);
    }
    size_t dot = execName.find_last_of('.');
    if (dot != std::string::npos)
    {
        execName = execName.substr(0, dot);
    }
    std::string lowerExec = execName;
    std::transform(lowerExec.begin(), lowerExec.end(), lowerExec.begin(), ::tolower);

    int argIndex = 1;
    auto cmd = registry.getCommand(lowerExec);
    if (cmd)
    {
        args.command = lowerExec;
    }
    else
    {
        if (argc < 2)
        {
            return args;
        }
        args.command = argv[1];
        argIndex = 2;
        cmd = registry.getCommand(args.command);
    }

    if (!cmd)
    {
        // Unknown command, collect remaining args as positional or unparsed flags
        for (int i = argIndex; i < argc; ++i)
        {
            args.positional.push_back(argv[i]);
        }
        return args;
    }

    if (cmd->hasSubcommands() && argIndex < argc && cmd->isSubcommand(argv[argIndex]))
    {
        args.subcommand = argv[argIndex++];
    }

    auto flagDefs = cmd->getFlagDefs(args.subcommand);
    std::map<std::string, FlagType> flagTypeMap;
    for (const auto& def : flagDefs)
    {
        std::string lower = def.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        flagTypeMap[lower] = def.type;
    }

    std::map<std::string, std::vector<std::string>> currentPositionalFlags;
    while (argIndex < argc)
    {
        std::string currentArg = argv[argIndex++];
        bool isFlag = false;
        if (!currentArg.empty())
        {
            if (currentArg[0] == '-')
            {
                isFlag = true;
            }
            else if (currentArg[0] == '/')
            {
                std::string flagName = currentArg.substr(1);
                std::string lower = flagName;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower == "?" || lower == "h" || lower == "help" || flagTypeMap.contains(lower))
                {
                    isFlag = true;
                }
            }
        }

        if (isFlag)
        {
            // It's a flag/switch. Strip leading / or - (and --)
            std::string flagName = currentArg.substr(1);
            if (!flagName.empty() && flagName[0] == '-')
            {
                flagName = flagName.substr(1);
            }
            std::string lower = flagName;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            auto it = flagTypeMap.find(lower);
            if (it != flagTypeMap.end())
            {
                if (it->second == FlagType::Boolean)
                {
                    args.flags[lower].push_back("true");
                    currentPositionalFlags[lower].push_back("true");
                }
                else
                {
                    // Takes a value
                    if (argIndex < argc)
                    {
                        std::string val = argv[argIndex++];
                        args.flags[lower].push_back(val);
                        currentPositionalFlags[lower].push_back(val);
                    }
                    else
                    {
                        args.flags[lower].push_back("");
                        currentPositionalFlags[lower].push_back("");
                    }
                }
            }
            else
            {
                args.flags[lower].push_back("true");
                currentPositionalFlags[lower].push_back("true");
            }
        }
        else
        {
            // Positional argument
            args.positional.push_back(currentArg);
            args.positionalFlags.push_back(currentPositionalFlags);
            currentPositionalFlags.clear();
        }
    }

    return args;
}

// CliParser is completely stateless

} // namespace cli
} // namespace ccky
