#ifndef CCKY_CERT_MGR_COMMAND_H
#define CCKY_CERT_MGR_COMMAND_H

#include <memory>

#include "cli/Command.h"
#include "crypto/ICertStore.h"

namespace ccky
{
namespace commands
{

class CertMgrCommand : public cli::Command
{
  public:
    explicit CertMgrCommand(
        std::istream& in = std::cin, std::ostream& out = std::cout, std::ostream& err = std::cerr);
    std::string getName() const override { return "certmgr"; }
    std::string getDescription() const override { return "Manages certificates, CTLs, and CRLs."; }
    bool hasSubcommands() const override { return true; }
    bool isSubcommand(const std::string& arg) const override;
    std::vector<cli::FlagDef> getFlagDefs(const std::string& subcommand) const override;
    void registerUsage(cli::CommandRegistry* registry) override;
    void printHelp() override;

  protected:
    int executeImpl(const cli::ParsedArgs& args) override;
    void displayError(const std::exception& e) override;
    void displayError(const std::string& msg) override;

  private:
    std::shared_ptr<crypto::ICertStore> getStore(const std::string& location, bool isSystemStore);
};

} // namespace commands
} // namespace ccky

#endif // CCKY_CERT_MGR_COMMAND_H
