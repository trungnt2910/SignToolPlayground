#include <ccky/app/signtool/command.h>

#include <ccky/app/backend.h>

namespace ccky {
namespace {

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

} // namespace

std::unique_ptr<Command> CreateSigntoolCommand()
{
    return std::make_unique<SigntoolCommand>();
}

} // namespace ccky
