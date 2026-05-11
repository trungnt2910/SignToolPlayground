#pragma once

#include <ccky/app/command.h>

namespace ccky {

std::unique_ptr<Command> CreateCertmgrCommand();

} // namespace ccky
