#ifndef CCKY_PVK2PFX_COMMAND_H
#define CCKY_PVK2PFX_COMMAND_H

#include "cli/Command.h"

namespace ccky
{
namespace commands
{

class Pvk2PfxCommand : public cli::Command
{
  public:
    using cli::Command::Command;

    std::string getName() const override { return "pvk2pfx"; }
    std::string getDescription() const override;
    bool hasSubcommands() const override { return false; }
    bool isSubcommand(const std::string& arg) const override { return false; }
    std::vector<cli::FlagDef> getFlagDefs(const std::string& subcommand) const override;
    void registerUsage(cli::CommandRegistry* registry) override;

  protected:
    void printHelp() override;
    int executeImpl(const cli::ParsedArgs& args) override;
    void displayError(const std::exception& e) override;
    void displayError(const std::string& msg) override;
};

} // namespace commands
} // namespace ccky

#endif // CCKY_PVK2PFX_COMMAND_H
