#include "commands/Pvk2PfxCommand.h"

#include <iostream>
#include <string>
#include <vector>

#include "cli/CommandRegistry.h"
#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"
#include "crypto/Pvk2PfxConverter.h"
#include "crypto/PvkKey.h"

namespace ccky
{
namespace commands
{

std::string Pvk2PfxCommand::getDescription() const
{
    return "Pvk2Pfx (pvk2pfx.exe) is a command-line tool copies public key and private key\n"
           "information contained in .spc, .cer, and .pvk files to a Personal Information\n"
           "Exchange (.pfx) file.";
}

std::vector<cli::FlagDef> Pvk2PfxCommand::getFlagDefs(const std::string& /*subcommand*/) const
{
    std::vector<cli::FlagDef> flags = {
        {"pvk", cli::FlagType::Value, "input PVK file name.", "<pvk-file>", ""},
        {"spc", cli::FlagType::Value, "input SPC file name.", "<spc-file>", ""},
        {"pfx", cli::FlagType::Value, "output PFX file name.", "<pfx-file>", ""},
        {"pi", cli::FlagType::Value, "PVK password.", "<pvk-pswd>", ""},
        {"po", cli::FlagType::Value, "PFX password; same as -pi if not given.", "<pfx-pswd>", ""},
        {"f", cli::FlagType::Boolean, "force overwrite existing PFX file.", "", ""},
        {"?", cli::FlagType::Boolean, "Displays help.", "", "", 0, "*", true},
        {"help", cli::FlagType::Boolean, "Displays help.", "", "", 0, "*", true},
    };
    return flags;
}

void Pvk2PfxCommand::registerUsage(cli::CommandRegistry* registry)
{
    cli::UsageBehavior behavior;
    behavior.useDashPrefix = true;
    behavior.noCategoryHeaders = true;
    behavior.flagPrefixSpaces = 8;
    behavior.dashSeparator = true;
    behavior.descriptionAfterFlags = true;
    behavior.basePadWidth = 25;

    registry->registerCommandUsage("pvk2pfx", "",
        "Usage:\n"
        "    pvk2pfx -pvk <pvk-file> [-pi <pvk-pswd>] -spc <spc-file>\n"
        "           [-pfx <pfx-file> [-po <pfx-pswd>] [-f]]\n",
        "        if -pfx option is not given, an export wizard will pop up. in\n"
        "        this case, options -po and -f are ignored.\n",
        {}, getFlagDefs(""), behavior);
}

void Pvk2PfxCommand::printHelp() {}

int Pvk2PfxCommand::executeImpl(const cli::ParsedArgs& args)
{
    if (args.flags.empty() && args.positional.empty())
    {
        if (m_registry)
        {
            m_err << m_registry->getUsage(getName(), "");
        }
        return 1;
    }

    crypto::Pvk2PfxOptions opts;
    opts.pvkFile = args.getFlagValue("pvk");
    opts.pvkPassword = args.getFlagValue("pi");
    opts.spcFile = args.getFlagValue("spc");
    opts.pfxFile = args.getFlagValue("pfx");
    opts.pfxPassword = args.getFlagValue("po");
    opts.force = args.hasFlag("f");

    if (opts.pvkFile.empty())
    {
        displayError("Input PVK file name must be specified.");
        return 1;
    }

    if (opts.spcFile.empty())
    {
        displayError("Input SPC file name must be specified.");
        return 1;
    }

    try
    {
        crypto::Pvk2PfxConverter::convert(opts);
        return 0;
    }
    catch (const crypto::PvkIncorrectPasswordException&)
    {
        displayError(
            "ERROR: Password incorrect or PVK file corrupted.\n(Error Code = 0x80090005).");
        return 1;
    }
    catch (const crypto::KeyMismatchException&)
    {
        displayError(
            "ERROR: Password incorrect or PVK file corrupted.\n(Error Code = 0x80090005).");
        return 1;
    }
    catch (const crypto::FileNotFoundException&)
    {
        displayError("ERROR: File not found.\n(Error Code = 0x80070002).");
        return 1;
    }
    catch (const crypto::OutputFileExistsException&)
    {
        displayError("ERROR: Output file exists.\n(Error Code = 0x80070050).");
        return 1;
    }
    catch (const crypto::PvkCorruptFileException&)
    {
        displayError("ERROR: An error occurred while reading or writing to a file.\n(Error Code = "
                     "0x80092003).");
        return 1;
    }
    catch (const std::exception&)
    {
        displayError("ERROR: An error occurred while reading or writing to a file.\n(Error Code = "
                     "0x80092003).");
        return 1;
    }
}

void Pvk2PfxCommand::displayError(const std::exception& e) { m_err << e.what() << "\n"; }

void Pvk2PfxCommand::displayError(const std::string& msg) { m_err << msg << "\n"; }

} // namespace commands
} // namespace ccky
