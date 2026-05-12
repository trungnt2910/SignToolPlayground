#include <ccky/app/application.h>

#include <ccky/app/certmgr/command.h>
#include <ccky/app/command.h>
#include <ccky/app/signtool/command.h>

#include <cwchar>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ccky {
namespace {

std::wstring WidenMessage(const std::string_view value)
{
    if (value.empty()) {
        return {};
    }

    std::mbstate_t state {};
    const char* source = value.data();
    const size_t length = std::mbsrtowcs(nullptr, &source, 0, &state);
    if (length == static_cast<size_t>(-1)) {
        return std::wstring(value.begin(), value.end());
    }

    std::wstring wide(length, L'\0');
    state = std::mbstate_t {};
    source = value.data();
    (void)std::mbsrtowcs(wide.data(), &source, wide.size(), &state);
    return wide;
}

std::vector<std::unique_ptr<Command>> CreateCommands()
{
    std::vector<std::unique_ptr<Command>> commands;
    commands.push_back(CreateSigntoolCommand());
    commands.push_back(CreateCertmgrCommand());
    return commands;
}

} // namespace

int RunApplication(
    const std::vector<std::wstring>& arguments,
    ICryptoBackend& backend,
    std::wostream& output,
    std::wostream& error)
{
    if (arguments.size() < 2) {
        error << L"Usage: ccky.exe <signtool|certmgr> [arguments...]\n";
        return 1;
    }

    ArgumentCursor cursor(arguments);
    const std::wstring command_name = cursor.Consume();

    for (const auto& command : CreateCommands()) {
        if (EqualsInsensitive(command->Name(), command_name)) {
            try {
                return command->Run(cursor, backend, output, error);
            } catch (const std::exception& exception) {
                error << L"ccky: " << WidenMessage(exception.what()) << L"\n";
                return 1;
            }
        }
    }

    error << L"Unsupported subcommand: " << command_name << L"\n";
    return 1;
}

} // namespace ccky
