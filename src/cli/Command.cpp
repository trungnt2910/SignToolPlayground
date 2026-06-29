#include "cli/Command.h"
#include "cli/CommandRegistry.h"

namespace ccky
{
namespace cli
{

int Command::execute(const ParsedArgs& args)
{
    // 1. Check for help triggers in FlagDefs
    auto flags = getFlagDefs(args.subcommand);
    for (const auto& f : flags)
    {
        if (!f.triggersHelpCategory.empty() && args.hasFlag(f.name))
        {
            if (m_registry)
            {
                std::string cat = f.triggersHelpCategory;
                if (cat == "*")
                {
                    cat = "";
                }
                m_err << m_registry->getUsage(getName(), args.subcommand, cat);
            }
            return 0;
        }
    }

    // 2. Run the actual command
    try
    {
        return executeImpl(args);
    }
    catch (const crypto::CckyException& e)
    {
        displayError(e);
        if (e.shouldPrintHelp())
        {
            printHelp();
        }
        return 1;
    }
    catch (const std::exception& e)
    {
        displayError(e);
        return 1;
    }
    catch (...)
    {
        displayError("Unknown error occurred.");
        return 1;
    }
}

} // namespace cli
} // namespace ccky
