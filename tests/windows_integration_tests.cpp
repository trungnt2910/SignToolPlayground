#include <ccky/app/application.h>
#include <ccky/app/backend.h>

#include <windows.h>
#include <wincrypt.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccky
{
namespace
{

    std::filesystem::path GetFixturePath(const std::wstring_view filename)
    {
        return std::filesystem::path(CCKY_TEST_SOURCE_DIR) / L"testdata" / filename;
    }

    std::filesystem::path
    MakeUniqueTemporaryPath(const std::wstring_view stem, const std::wstring_view extension)
    {
        std::wstring prefix(stem.substr(0, std::min<size_t>(stem.size(), 3U)));
        if (prefix.size() < 3)
        {
            prefix.append(3 - prefix.size(), L'x');
        }

        std::wstring temp_file(MAX_PATH, L'\0');
        const UINT result = GetTempFileNameW(
            std::filesystem::temp_directory_path().c_str(), prefix.c_str(), 0, temp_file.data());
        if (result == 0)
        {
            throw std::runtime_error("Failed to allocate a temporary file path.");
        }

        temp_file.resize(wcslen(temp_file.c_str()));
        std::filesystem::path path(temp_file);
        if (!extension.empty())
        {
            std::error_code error;
            std::filesystem::remove(path, error);
            path.replace_extension(extension);
        }
        return path;
    }

    std::string WideToUtf8(const std::wstring_view value)
    {
        if (value.empty())
        {
            return {};
        }

        const int size = WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<size_t>(size), '\0');
        (void)WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            utf8.data(),
            size,
            nullptr,
            nullptr);
        return utf8;
    }

    struct CertContextDeleter
    {
        void operator()(const CERT_CONTEXT* certificate) const
        {
            if (certificate != nullptr)
            {
                CertFreeCertificateContext(certificate);
            }
        }
    };

    struct CertStoreDeleter
    {
        void operator()(void* store) const
        {
            if (store != nullptr)
            {
                CertCloseStore(reinterpret_cast<HCERTSTORE>(store), 0);
            }
        }
    };

    using UniqueCertContext = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
    using UniqueCertStore = std::unique_ptr<void, CertStoreDeleter>;

    std::wstring QuotePowerShellLiteral(const std::wstring& value)
    {
        std::wstring quoted = L"'";
        for (const wchar_t character : value)
        {
            if (character == L'\'')
            {
                quoted += L"''";
            }
            else
            {
                quoted += character;
            }
        }
        quoted += L"'";
        return quoted;
    }

    std::optional<std::filesystem::path> ResolvePowerShellExecutable()
    {
        std::vector<std::filesystem::path> candidates;

        std::wstring system_root(MAX_PATH, L'\0');
        const DWORD system_root_length = GetEnvironmentVariableW(
            L"SystemRoot", system_root.data(), static_cast<DWORD>(system_root.size()));
        if (system_root_length > 0 && system_root_length < system_root.size())
        {
            system_root.resize(system_root_length);
            candidates.emplace_back(
                std::filesystem::path(system_root) / L"System32" / L"WindowsPowerShell" / L"v1.0" /
                L"powershell.exe");
        }

        candidates.emplace_back(L"powershell.exe");
        candidates.emplace_back(L"pwsh.exe");

        for (const auto& candidate : candidates)
        {
            if (candidate.is_absolute())
            {
                if (std::filesystem::exists(candidate))
                {
                    return candidate;
                }
                continue;
            }

            std::wstring resolved(MAX_PATH, L'\0');
            const DWORD resolved_length = SearchPathW(
                nullptr,
                candidate.c_str(),
                nullptr,
                static_cast<DWORD>(resolved.size()),
                resolved.data(),
                nullptr);
            if (resolved_length > 0 && resolved_length < resolved.size())
            {
                resolved.resize(resolved_length);
                return std::filesystem::path(resolved);
            }
        }

        return std::nullopt;
    }

    int RunPowerShellScript(const std::wstring& script)
    {
        static const std::optional<std::filesystem::path> shell_path =
            ResolvePowerShellExecutable();
        if (!shell_path.has_value())
        {
            return -1;
        }

        const std::filesystem::path script_path =
            MakeUniqueTemporaryPath(L"ccky-test-script", L".ps1");
        std::ofstream stream(script_path);
        if (!stream.is_open())
        {
            return -1;
        }
        stream << WideToUtf8(
            L"if (-not (Get-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue)) {"
            L"Import-Module Microsoft.PowerShell.Security -ErrorAction Stop }; "
            L"if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) { "
            L"New-PSDrive -Name Cert -PSProvider Certificate -Root '\\' | Out-Null }; " +
            script);
        stream.close();

        std::wstring command_line =
            L"\"" + shell_path->wstring() +
            L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
            script_path.wstring() + L"\"";

        STARTUPINFOW startup_info{};
        startup_info.cb = sizeof(startup_info);
        PROCESS_INFORMATION process_information{};
        int exit_code = -1;
        if (CreateProcessW(
                nullptr,
                command_line.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                nullptr,
                &startup_info,
                &process_information))
        {
            (void)WaitForSingleObject(process_information.hProcess, INFINITE);
            DWORD process_exit_code = 1;
            if (GetExitCodeProcess(process_information.hProcess, &process_exit_code) != 0)
            {
                exit_code = static_cast<int>(process_exit_code);
            }
            CloseHandle(process_information.hThread);
            CloseHandle(process_information.hProcess);
        }

        std::error_code error;
        std::filesystem::remove(script_path, error);
        return exit_code;
    }

    bool HasPowerShellCertificateSupport()
    {
        static const bool supported = [] {
            const std::filesystem::path probe_path =
                MakeUniqueTemporaryPath(L"ccky-powershell-probe", L".txt");
            const int exit_code = RunPowerShellScript(
                L"Get-ChildItem Cert:\\CurrentUser\\My | Out-Null; "
                L"Set-Content -LiteralPath " +
                QuotePowerShellLiteral(probe_path.wstring()) + L" -Value 'ok' -NoNewline");
            if (exit_code != 0 || !std::filesystem::exists(probe_path))
            {
                std::error_code error;
                std::filesystem::remove(probe_path, error);
                return false;
            }

            std::wifstream stream(probe_path);
            std::wstring value;
            std::getline(stream, value);

            std::error_code error;
            std::filesystem::remove(probe_path, error);
            return value == L"ok";
        }();
        return supported;
    }

    std::wstring ReadFileAsWideString(const std::filesystem::path& path)
    {
        std::wifstream stream(path);
        if (!stream.is_open())
        {
            throw std::runtime_error("Failed to open the expected text file.");
        }
        std::wstring value;
        std::getline(stream, value);
        return value;
    }

    std::vector<unsigned char> ReadBinaryFile(const std::filesystem::path& path)
    {
        std::ifstream stream(path, std::ios::binary);
        if (!stream.is_open())
        {
            throw std::runtime_error("Failed to open the expected binary file.");
        }
        return std::vector<unsigned char>(
            std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    }

    class TemporaryCodeSigningCertificate
    {
    public:
        explicit TemporaryCodeSigningCertificate(const std::wstring& subject_name) :
            subject_name_(subject_name)
        {
            exported_certificate_path_ = MakeUniqueTemporaryPath(L"ccky-exported", L".cer");
            thumbprint_path_ = MakeUniqueTemporaryPath(L"ccky-thumbprint", L".txt");

            const int exit_code = RunPowerShellScript(
                L"$cert = New-SelfSignedCertificate -Subject " +
                QuotePowerShellLiteral(subject_name_) +
                L" -Type CodeSigningCert -CertStoreLocation Cert:\\CurrentUser\\My; "
                L"Export-Certificate -Cert $cert -FilePath " +
                QuotePowerShellLiteral(exported_certificate_path_.wstring()) +
                L" -Force | Out-Null; "
                L"Set-Content -LiteralPath " +
                QuotePowerShellLiteral(thumbprint_path_.wstring()) +
                L" -Value $cert.Thumbprint -NoNewline");
            if (exit_code != 0)
            {
                throw std::runtime_error("Failed to create a temporary code signing certificate.");
            }
            thumbprint_ = ReadFileAsWideString(thumbprint_path_);
        }

        ~TemporaryCodeSigningCertificate()
        {
            if (!thumbprint_.empty())
            {
                const int exit_code = RunPowerShellScript(
                    L"Remove-Item -LiteralPath " +
                    QuotePowerShellLiteral(L"Cert:\\CurrentUser\\My\\" + thumbprint_));
                if (exit_code != 0)
                {
                    OutputDebugStringW(
                        L"CCKY test cleanup failed to remove temporary certificate.\n");
                }
            }
        }

        [[nodiscard]] const std::wstring& SubjectName() const
        {
            return subject_name_;
        }

        [[nodiscard]] const std::filesystem::path& ExportedCertificatePath() const
        {
            return exported_certificate_path_;
        }

    private:
        std::wstring subject_name_;
        std::wstring thumbprint_;
        std::filesystem::path exported_certificate_path_;
        std::filesystem::path thumbprint_path_;
    };

    UniqueCertStore OpenCertificateStoreFromFile(const std::filesystem::path& path)
    {
        HCERTSTORE store = nullptr;
        if (!CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                nullptr,
                nullptr,
                nullptr,
                &store,
                nullptr,
                nullptr))
        {
            return {};
        }

        return UniqueCertStore(store);
    }

    UniqueCertContext GetFirstCertificate(const HCERTSTORE store)
    {
        const CERT_CONTEXT* certificate = CertEnumCertificatesInStore(store, nullptr);
        if (certificate == nullptr)
        {
            return {};
        }

        return UniqueCertContext(certificate);
    }

    std::wstring GetSubjectString(const CERT_CONTEXT* certificate)
    {
        const DWORD length =
            CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        std::wstring name(length, L'\0');
        (void)CertGetNameStringW(
            certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), length);
        if (!name.empty() && name.back() == L'\0')
        {
            name.pop_back();
        }
        return name;
    }

    TEST(WindowsIntegrationTests, SigntoolSignsCheckedInPeFixture)
    {
        if (!HasPowerShellCertificateSupport())
        {
            GTEST_SKIP() << "Windows integration tests require classic Windows PowerShell "
                            "certificate provider support.";
        }

        const std::filesystem::path unsigned_pe = GetFixturePath(L"minimal-x64.exe");
        const std::filesystem::path working_copy =
            std::filesystem::temp_directory_path() / L"ccky-signed.exe";
        std::filesystem::copy_file(
            unsigned_pe, working_copy, std::filesystem::copy_options::overwrite_existing);

        TemporaryCodeSigningCertificate certificate(L"CN=CCKY Signtool Test");
        auto backend = CreatePlatformBackend();
        std::wostringstream output;
        std::wostringstream error;

        ASSERT_EQ(
            RunApplication(
                {
                    L"ccky.exe",
                    L"signtool",
                    L"sign",
                    L"/v",
                    L"/fd",
                    L"sha256",
                    L"/n",
                    L"CCKY Signtool Test",
                    working_copy.wstring(),
                },
                *backend,
                output,
                error),
            0)
            << std::string(error.str().begin(), error.str().end());

        const auto store = OpenCertificateStoreFromFile(working_copy);
        ASSERT_TRUE(static_cast<bool>(store));
        const auto signed_certificate =
            GetFirstCertificate(reinterpret_cast<HCERTSTORE>(store.get()));
        ASSERT_TRUE(static_cast<bool>(signed_certificate));
        EXPECT_EQ(GetSubjectString(signed_certificate.get()), L"CCKY Signtool Test");
    }

    TEST(WindowsIntegrationTests, CertmgrExportsCertificateFromSignedPe)
    {
        if (!HasPowerShellCertificateSupport())
        {
            GTEST_SKIP() << "Windows integration tests require classic Windows PowerShell "
                            "certificate provider support.";
        }

        const std::filesystem::path unsigned_pe = GetFixturePath(L"minimal-x64.exe");
        const std::filesystem::path working_copy =
            std::filesystem::temp_directory_path() / L"ccky-export-source.exe";
        const std::filesystem::path exported_certificate =
            std::filesystem::temp_directory_path() / L"ccky-exported.cer";
        std::filesystem::copy_file(
            unsigned_pe, working_copy, std::filesystem::copy_options::overwrite_existing);

        TemporaryCodeSigningCertificate certificate(L"CN=CCKY Certmgr Test");
        auto backend = CreatePlatformBackend();
        std::wostringstream output;
        std::wostringstream error;

        ASSERT_EQ(
            RunApplication(
                {
                    L"ccky.exe",
                    L"signtool",
                    L"sign",
                    L"/fd",
                    L"sha256",
                    L"/n",
                    L"CCKY Certmgr Test",
                    working_copy.wstring(),
                },
                *backend,
                output,
                error),
            0)
            << std::string(error.str().begin(), error.str().end());

        output.str(L"");
        output.clear();
        error.str(L"");
        error.clear();

        ASSERT_EQ(
            RunApplication(
                {
                    L"ccky.exe",
                    L"certmgr",
                    L"/put",
                    L"/c",
                    working_copy.wstring(),
                    exported_certificate.wstring(),
                },
                *backend,
                output,
                error),
            0)
            << std::string(error.str().begin(), error.str().end());

        EXPECT_EQ(
            ReadBinaryFile(exported_certificate),
            ReadBinaryFile(certificate.ExportedCertificatePath()));
    }

} // namespace
} // namespace ccky
