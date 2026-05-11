#include <ccky/app/application.h>

#include <ccky/app/backend.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace ccky {
namespace {

bool EqualsInsensitive(const std::wstring_view left, const std::wstring_view right)
{
    return std::equal(
        left.begin(),
        left.end(),
        right.begin(),
        right.end(),
        [](const wchar_t lhs, const wchar_t rhs) {
            return std::towlower(lhs) == std::towlower(rhs);
        });
}

bool IsSwitch(const std::wstring_view token)
{
    return !token.empty() && (token.front() == L'/' || token.front() == L'-');
}

std::wstring WidenMessage(const std::string_view value)
{
#if defined(_WIN32)
    if (value.empty()) {
        return {};
    }

    int length = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (length == 0) {
        length = MultiByteToWideChar(
            CP_ACP,
            0,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0);
        if (length == 0) {
            return std::wstring(value.begin(), value.end());
        }

        std::wstring wide(static_cast<size_t>(length), L'\0');
        (void)MultiByteToWideChar(
            CP_ACP,
            0,
            value.data(),
            static_cast<int>(value.size()),
            wide.data(),
            length);
        return wide;
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    (void)MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        wide.data(),
        length);
    return wide;
#else
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
#endif
}

class ArgumentCursor {
public:
    explicit ArgumentCursor(const std::vector<std::wstring>& arguments) : arguments_(arguments), index_(1) {}

    [[nodiscard]] bool HasMore() const
    {
        return index_ < arguments_.size();
    }

    [[nodiscard]] const std::wstring& Peek() const
    {
        return arguments_.at(index_);
    }

    std::wstring Consume()
    {
        return arguments_.at(index_++);
    }

private:
    const std::vector<std::wstring>& arguments_;
    size_t index_;
};

class Command {
public:
    virtual ~Command() = default;

    [[nodiscard]] virtual std::wstring_view Name() const = 0;
    virtual int Run(ArgumentCursor& cursor, ICryptoBackend& backend, std::wostream& output, std::wostream& error) const = 0;
};

class SigntoolCommand final : public Command {
public:
    [[nodiscard]] std::wstring_view Name() const override
    {
        return L"signtool";
    }

    int Run(ArgumentCursor& cursor, ICryptoBackend& backend, std::wostream& output, std::wostream& error) const override
    {
        if (!cursor.HasMore() || !EqualsInsensitive(cursor.Consume(), L"sign")) {
            error << L"signtool currently supports only the 'sign' command.\n";
            return 1;
        }

        SignRequest request{};
        while (cursor.HasMore() && IsSwitch(cursor.Peek())) {
            const std::wstring option = cursor.Consume();
            if (EqualsInsensitive(option, L"/v") || EqualsInsensitive(option, L"-v")) {
                request.verbose = true;
                continue;
            }

            if (EqualsInsensitive(option, L"/fd") || EqualsInsensitive(option, L"-fd")) {
                if (!cursor.HasMore()) {
                    error << L"signtool sign requires a value for /fd.\n";
                    return 1;
                }

                request.file_digest_algorithm = cursor.Consume();
                continue;
            }

            if (EqualsInsensitive(option, L"/n") || EqualsInsensitive(option, L"-n")) {
                if (!cursor.HasMore()) {
                    error << L"signtool sign requires a value for /n.\n";
                    return 1;
                }

                request.subject_name = cursor.Consume();
                continue;
            }

            error << L"Unsupported signtool switch: " << option << L"\n";
            return 1;
        }

        if (request.file_digest_algorithm.empty()) {
            error << L"signtool sign requires /fd.\n";
            return 1;
        }

        if (!EqualsInsensitive(request.file_digest_algorithm, L"sha256")) {
            error << L"signtool sign currently supports only /fd sha256.\n";
            return 1;
        }

        if (request.subject_name.empty()) {
            error << L"signtool sign requires /n.\n";
            return 1;
        }

        if (!cursor.HasMore()) {
            error << L"signtool sign requires a PE file path.\n";
            return 1;
        }

        request.file_path = cursor.Consume();
        if (cursor.HasMore()) {
            error << L"signtool sign accepts exactly one PE file path.\n";
            return 1;
        }

        backend.SignFile(request);
        if (request.verbose) {
            output << L"Successfully signed " << request.file_path.wstring() << L" using /fd "
                   << request.file_digest_algorithm << L".\n";
        }
        return 0;
    }
};

class CertmgrCommand final : public Command {
public:
    [[nodiscard]] std::wstring_view Name() const override
    {
        return L"certmgr";
    }

    int Run(ArgumentCursor& cursor, ICryptoBackend& backend, std::wostream& output, std::wostream& error) const override
    {
        bool saw_put = false;
        bool saw_c = false;
        std::vector<std::wstring> positional_arguments;

        while (cursor.HasMore()) {
            if (!IsSwitch(cursor.Peek())) {
                positional_arguments.push_back(cursor.Consume());
                continue;
            }

            const std::wstring option = cursor.Consume();
            if (EqualsInsensitive(option, L"/put") || EqualsInsensitive(option, L"-put")) {
                saw_put = true;
                continue;
            }

            if (EqualsInsensitive(option, L"/c") || EqualsInsensitive(option, L"-c")) {
                saw_c = true;
                continue;
            }

            error << L"Unsupported certmgr switch: " << option << L"\n";
            return 1;
        }

        if (!saw_put || !saw_c) {
            error << L"certmgr currently requires /put /c.\n";
            return 1;
        }

        if (positional_arguments.size() != 2) {
            error << L"certmgr /put /c requires <source-store> <output-certificate>.\n";
            return 1;
        }

        backend.ExportCertificate(ExportCertificateRequest {
            positional_arguments.at(0),
            positional_arguments.at(1),
        });
        output << L"Exported certificate to " << positional_arguments.at(1) << L".\n";
        return 0;
    }
};

std::vector<std::unique_ptr<Command>> CreateCommands()
{
    std::vector<std::unique_ptr<Command>> commands;
    commands.push_back(std::make_unique<SigntoolCommand>());
    commands.push_back(std::make_unique<CertmgrCommand>());
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
