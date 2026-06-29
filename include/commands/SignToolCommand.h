#ifndef CCKY_SIGN_TOOL_COMMAND_H
#define CCKY_SIGN_TOOL_COMMAND_H

#include "cli/Command.h"

namespace ccky
{
namespace commands
{

class SignToolCommand : public cli::Command
{
  public:
    explicit SignToolCommand(
        std::istream& in = std::cin, std::ostream& out = std::cout, std::ostream& err = std::cerr);
    std::string getName() const override { return "signtool"; }
    std::string getDescription() const override
    {
        return "Digitally signs, verifies, and timestamps files.";
    }
    bool hasSubcommands() const override { return true; }
    bool isSubcommand(const std::string& arg) const override;
    std::vector<cli::FlagDef> getFlagDefs(const std::string& subcommand) const override;
    void registerUsage(cli::CommandRegistry* registry) override;
    void printHelp() override;

  private:
    std::vector<cli::FlagDef> getFlagDefsInternal(const std::string& subcommand) const;

  protected:
    int executeImpl(const cli::ParsedArgs& args) override;
    void displayError(const std::exception& e) override;
    void displayError(const std::string& msg) override;

  private:
    std::string m_currentSubcommand;
};

} // namespace commands
} // namespace ccky

#endif // CCKY_SIGN_TOOL_COMMAND_H
