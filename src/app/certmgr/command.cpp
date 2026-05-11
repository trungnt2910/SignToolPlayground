#include <ccky/app/certmgr/command.h>

#include <ccky/app/backend.h>

namespace ccky {
namespace {

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

} // namespace

std::unique_ptr<Command> CreateCertmgrCommand()
{
    return std::make_unique<CertmgrCommand>();
}

} // namespace ccky
