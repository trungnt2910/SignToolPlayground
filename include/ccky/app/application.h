#pragma once

#include <string>
#include <vector>

namespace ccky {

class ICryptoBackend;

int RunApplication(
    const std::vector<std::wstring>& arguments,
    ICryptoBackend& backend,
    std::wostream& output,
    std::wostream& error);

} // namespace ccky
