#ifndef CCKY_COMMANDS_MAKECERT_COMMAND_H
#define CCKY_COMMANDS_MAKECERT_COMMAND_H

#include <exception>
#include <string>
#include <vector>

#include "cli/Command.h"

namespace ccky
{
namespace commands
{

// The default name "Joe's Software Emporium" is intentionally hard-coded here.
// As per the Microsoft docs, if -n is not passed, this exact name is used.
constexpr const char* MAKECERT_DEFAULT_SUBJECT_NAME = "CN=Joe's Software Emporium";

class MakeCertCommand : public cli::Command
{
  public:
    using cli::Command::Command;

    std::string getName() const override { return "makecert"; }
    std::string getDescription() const override;
    bool hasSubcommands() const override { return false; }
    bool isSubcommand(const std::string& arg) const override { return false; }
    std::vector<cli::FlagDef> getFlagDefs(const std::string& subcommand) const override;
    void registerUsage(cli::CommandRegistry* registry) override;
    void printHelp() override;

  protected:
    int executeImpl(const cli::ParsedArgs& args) override;
    void displayError(const std::exception& e) override;
    void displayError(const std::string& msg) override;
};

} // namespace commands
} // namespace ccky

#endif // CCKY_COMMANDS_MAKECERT_COMMAND_H
