#ifndef CCKY_CLI_PARSER_H
#define CCKY_CLI_PARSER_H

#include <string>
#include <vector>

#include "cli/Command.h"
#include "cli/CommandRegistry.h"

namespace ccky
{
namespace cli
{

class CliParser
{
  public:
    static ParsedArgs parse(int argc, const char* const argv[], const CommandRegistry& registry);
};

} // namespace cli
} // namespace ccky

#endif // CCKY_CLI_PARSER_H
