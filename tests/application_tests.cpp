#include <ccky/app/application.h>
#include <ccky/app/backend.h>

#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>

namespace ccky {
namespace {

class FakeBackend final : public ICryptoBackend {
public:
    void SignFile(const SignRequest& request) override
    {
        sign_requests.push_back(request);
    }

    void ExportCertificate(const ExportCertificateRequest& request) override
    {
        export_requests.push_back(request);
    }

    std::vector<SignRequest> sign_requests;
    std::vector<ExportCertificateRequest> export_requests;
};

TEST(ApplicationTests, SigntoolSignParsesMandatoryInvocation)
{
    FakeBackend backend;
    std::wostringstream output;
    std::wostringstream error;

    const int exit_code = RunApplication(
        {
            L"ccky.exe",
            L"signtool",
            L"sign",
            L"/v",
            L"/fd",
            L"sha256",
            L"/n",
            L"Example Subject",
            L"sample.exe",
        },
        backend,
        output,
        error);

    ASSERT_EQ(exit_code, 0);
    ASSERT_TRUE(error.str().empty());
    ASSERT_EQ(backend.sign_requests.size(), 1U);
    EXPECT_TRUE(backend.sign_requests.front().verbose);
    EXPECT_EQ(backend.sign_requests.front().file_digest_algorithm, L"sha256");
    EXPECT_EQ(backend.sign_requests.front().subject_name, L"Example Subject");
    EXPECT_EQ(backend.sign_requests.front().file_path, std::filesystem::path(L"sample.exe"));
    EXPECT_NE(output.str().find(L"Successfully signed"), std::wstring::npos);
}

TEST(ApplicationTests, CertmgrPutParsesMandatoryInvocation)
{
    FakeBackend backend;
    std::wostringstream output;
    std::wostringstream error;

    const int exit_code = RunApplication(
        {
            L"ccky.exe",
            L"certmgr",
            L"/put",
            L"/c",
            L"signed.exe",
            L"exported.cer",
        },
        backend,
        output,
        error);

    ASSERT_EQ(exit_code, 0);
    ASSERT_TRUE(error.str().empty());
    ASSERT_EQ(backend.export_requests.size(), 1U);
    EXPECT_EQ(backend.export_requests.front().source_store_path, std::filesystem::path(L"signed.exe"));
    EXPECT_EQ(backend.export_requests.front().output_certificate_path, std::filesystem::path(L"exported.cer"));
    EXPECT_NE(output.str().find(L"Exported certificate"), std::wstring::npos);
}

} // namespace
} // namespace ccky
