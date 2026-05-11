#pragma once

#include <filesystem>
#include <memory>
#include <string>

namespace ccky {

struct SignRequest {
    bool verbose = false;
    std::wstring file_digest_algorithm;
    std::wstring subject_name;
    std::filesystem::path file_path;
};

struct ExportCertificateRequest {
    std::filesystem::path source_store_path;
    std::filesystem::path output_certificate_path;
};

class ICryptoBackend {
public:
    virtual ~ICryptoBackend() = default;

    virtual void SignFile(const SignRequest& request) = 0;
    virtual void ExportCertificate(const ExportCertificateRequest& request) = 0;
};

std::unique_ptr<ICryptoBackend> CreatePlatformBackend();

} // namespace ccky
