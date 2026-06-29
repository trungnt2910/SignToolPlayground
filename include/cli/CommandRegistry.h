#ifndef CCKY_COMMAND_REGISTRY_H
#define CCKY_COMMAND_REGISTRY_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cli/Command.h"

namespace ccky
{
namespace cli
{

class CommandRegistry
{
  public:
    void registerCommand(std::shared_ptr<Command> command);
    std::shared_ptr<Command> getCommand(const std::string& name) const;
    std::vector<std::shared_ptr<Command>> getAllCommands() const;

    void registerCommandUsage(const std::string& command, const std::string& subcommand,
        const std::string& usageHeader, const std::string& cmdDescription,
        const std::vector<SubcommandInfo>& subcommands, const std::vector<FlagDef>& flags,
        UsageBehavior behavior = UsageBehavior{});
    std::string getUsage(const std::string& command, const std::string& subcommand,
        const std::string& categoryFilter = "") const;
    const UsageBehavior* getBehavior(
        const std::string& command, const std::string& subcommand = "") const;

  private:
    std::map<std::string, std::shared_ptr<Command>> m_commands;
    std::map<std::pair<std::string, std::string>, UsageInfo> m_usageRegistry;
};

} // namespace cli
} // namespace ccky

#endif // CCKY_COMMAND_REGISTRY_H
