#include <iostream>
#include <memory>

#include "cli/CliParser.h"
#include "cli/CommandRegistry.h"
#include "commands/CertMgrCommand.h"
#include "commands/SignToolCommand.h"

int main(int argc, char* argv[])
{
    ccky::cli::CommandRegistry registry;
    registry.registerCommandUsage("ccky", "", "Usage: ccky <command> [options]\n", "",
        {{"certmgr", "Manages certificates, CTLs, and CRLs."},
            {"signtool", "Digitally signs, verifies, and timestamps files."}},
        {});

    registry.registerCommand(std::make_shared<ccky::commands::CertMgrCommand>());
    registry.registerCommand(std::make_shared<ccky::commands::SignToolCommand>());

    auto args = ccky::cli::CliParser::parse(argc, argv, registry);
    if (args.command.empty() || args.command == "/?" || args.command == "-?" ||
        args.command == "/help" || args.command == "-help" || args.command == "?")
    {
        std::cerr << registry.getUsage("ccky", "");
        return 0;
    }

    auto cmd = registry.getCommand(args.command);
    if (!cmd)
    {
        std::cerr << "Error: Unknown command '" << args.command << "'.\n";
        return 1;
    }

    return cmd->execute(args);
}
