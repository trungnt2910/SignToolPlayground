#include <ccky/app/application.h>
#include <ccky/app/backend.h>

#include <windows.h>
#include <wincrypt.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccky {
namespace {

std::filesystem::path GetFixturePath(const std::wstring_view filename)
{
    return std::filesystem::path(CCKY_TEST_SOURCE_DIR) / L"testdata" / filename;
}

std::filesystem::path MakeUniqueTemporaryPath(const std::wstring_view stem, const std::wstring_view extension)
{
    std::wstring prefix(stem.substr(0, std::min<size_t>(stem.size(), 3U)));
    if (prefix.size() < 3) {
        prefix.append(3 - prefix.size(), L'x');
    }

    std::wstring temp_file(MAX_PATH, L'\0');
    const UINT result = GetTempFileNameW(
        std::filesystem::temp_directory_path().c_str(),
        prefix.c_str(),
        0,
        temp_file.data());
    if (result == 0) {
        throw std::runtime_error("Failed to allocate a temporary file path.");
    }

    temp_file.resize(wcslen(temp_file.c_str()));
    std::filesystem::path path(temp_file);
    if (!extension.empty()) {
        std::error_code error;
        std::filesystem::remove(path, error);
        path.replace_extension(extension);
    }
    return path;
}

std::string WideToUtf8(const std::wstring_view value)
{
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
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

struct CertContextDeleter {
    void operator()(const CERT_CONTEXT* certificate) const
    {
        if (certificate != nullptr) {
            CertFreeCertificateContext(certificate);
        }
    }
};

struct CertStoreDeleter {
    void operator()(void* store) const
    {
        if (store != nullptr) {
            CertCloseStore(reinterpret_cast<HCERTSTORE>(store), 0);
        }
    }
};

using UniqueCertContext = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
using UniqueCertStore = std::unique_ptr<void, CertStoreDeleter>;

std::wstring QuotePowerShellLiteral(const std::wstring& value)
{
    std::wstring quoted = L"'";
    for (const wchar_t character : value) {
        if (character == L'\'') {
            quoted += L"''";
        } else {
            quoted += character;
        }
    }
    quoted += L"'";
    return quoted;
}

int RunPowerShellScript(const std::wstring& script)
{
    const std::filesystem::path script_path = MakeUniqueTemporaryPath(L"ccky-test-script", L".ps1");
    std::ofstream stream(script_path);
    if (!stream.is_open()) {
        return -1;
    }
    stream << WideToUtf8(script);
    stream.close();

    const std::wstring command = L"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                                 script_path.wstring() + L"\"";
    const int exit_code = _wsystem(command.c_str());
    std::error_code error;
    std::filesystem::remove(script_path, error);
    return exit_code;
}

std::wstring ReadFileAsWideString(const std::filesystem::path& path)
{
    std::wifstream stream(path);
    if (!stream.is_open()) {
        throw std::runtime_error("Failed to open the expected text file.");
    }
    std::wstring value;
    std::getline(stream, value);
    return value;
}

std::vector<unsigned char> ReadBinaryFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        throw std::runtime_error("Failed to open the expected binary file.");
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

class TemporaryCodeSigningCertificate {
public:
    explicit TemporaryCodeSigningCertificate(const std::wstring& subject_name)
        : subject_name_(subject_name)
    {
        exported_certificate_path_ = MakeUniqueTemporaryPath(L"ccky-exported", L".cer");
        thumbprint_path_ = MakeUniqueTemporaryPath(L"ccky-thumbprint", L".txt");

        const int exit_code = RunPowerShellScript(
            L"$cert = New-SelfSignedCertificate -Subject " + QuotePowerShellLiteral(subject_name_) +
            L" -Type CodeSigningCert -CertStoreLocation Cert:\\CurrentUser\\My; "
            L"Export-Certificate -Cert $cert -FilePath " + QuotePowerShellLiteral(exported_certificate_path_.wstring()) +
            L" -Force | Out-Null; "
            L"Set-Content -LiteralPath " + QuotePowerShellLiteral(thumbprint_path_.wstring()) +
            L" -Value $cert.Thumbprint -NoNewline");
        if (exit_code != 0) {
            throw std::runtime_error("Failed to create a temporary code signing certificate.");
        }
        thumbprint_ = ReadFileAsWideString(thumbprint_path_);
    }

    ~TemporaryCodeSigningCertificate()
    {
        if (!thumbprint_.empty()) {
            const int exit_code = RunPowerShellScript(
                L"Remove-Item -LiteralPath " + QuotePowerShellLiteral(L"Cert:\\CurrentUser\\My\\" + thumbprint_));
            if (exit_code != 0) {
                OutputDebugStringW(L"CCKY test cleanup failed to remove temporary certificate.\n");
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
            nullptr)) {
        return {};
    }

    return UniqueCertStore(store);
}

UniqueCertContext GetFirstCertificate(const HCERTSTORE store)
{
    const CERT_CONTEXT* certificate = CertEnumCertificatesInStore(store, nullptr);
    if (certificate == nullptr) {
        return {};
    }

    return UniqueCertContext(certificate);
}

std::wstring GetSubjectString(const CERT_CONTEXT* certificate)
{
    const DWORD length = CertGetNameStringW(
        certificate,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        nullptr,
        0);
    std::wstring name(length, L'\0');
    (void)CertGetNameStringW(
        certificate,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        name.data(),
        length);
    if (!name.empty() && name.back() == L'\0') {
        name.pop_back();
    }
    return name;
}

TEST(WindowsIntegrationTests, SigntoolSignsCheckedInPeFixture)
{
    const std::filesystem::path unsigned_pe = GetFixturePath(L"minimal-x64.exe");
    const std::filesystem::path working_copy = std::filesystem::temp_directory_path() / L"ccky-signed.exe";
    std::filesystem::copy_file(unsigned_pe, working_copy, std::filesystem::copy_options::overwrite_existing);

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
    const auto signed_certificate = GetFirstCertificate(reinterpret_cast<HCERTSTORE>(store.get()));
    ASSERT_TRUE(static_cast<bool>(signed_certificate));
    EXPECT_EQ(GetSubjectString(signed_certificate.get()), L"CCKY Signtool Test");
}

TEST(WindowsIntegrationTests, CertmgrExportsCertificateFromSignedPe)
{
    const std::filesystem::path unsigned_pe = GetFixturePath(L"minimal-x64.exe");
    const std::filesystem::path working_copy = std::filesystem::temp_directory_path() / L"ccky-export-source.exe";
    const std::filesystem::path exported_certificate = std::filesystem::temp_directory_path() / L"ccky-exported.cer";
    std::filesystem::copy_file(unsigned_pe, working_copy, std::filesystem::copy_options::overwrite_existing);

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

    EXPECT_EQ(ReadBinaryFile(exported_certificate), ReadBinaryFile(certificate.ExportedCertificatePath()));
}

} // namespace
} // namespace ccky
