#include <ccky/app/backend.h>

#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <wil/resource.h>

#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccky
{
namespace
{

    struct SIGNER_FILE_INFO
    {
        DWORD cbSize;
        LPCWSTR pwszFileName;
        HANDLE hFile;
    };

    struct SIGNER_SUBJECT_INFO
    {
        DWORD cbSize;
        DWORD* pdwIndex;
        DWORD dwSubjectChoice;
        union
        {
            SIGNER_FILE_INFO* pSignerFileInfo;
            void* unused;
        };
    };

    struct SIGNER_CERT_STORE_INFO
    {
        DWORD cbSize;
        PCCERT_CONTEXT pSigningCert;
        DWORD dwCertPolicy;
        HCERTSTORE hCertStore;
    };

    struct SIGNER_CERT
    {
        DWORD cbSize;
        DWORD dwCertChoice;
        union
        {
            SIGNER_CERT_STORE_INFO* pCertStoreInfo;
            void* unused;
        };
        HWND hwnd;
    };

    struct SIGNER_SIGNATURE_INFO
    {
        DWORD cbSize;
        ALG_ID algidHash;
        DWORD dwAttrChoice;
        void* pAttrAuthcode;
        void* psAuthenticated;
        void* psUnauthenticated;
    };

    struct SIGNER_CONTEXT
    {
        DWORD cbSize;
        DWORD cbBlob;
        BYTE* pbBlob;
    };

    using SignerSignExFunction = HRESULT(WINAPI*)(
        DWORD,
        SIGNER_SUBJECT_INFO*,
        SIGNER_CERT*,
        SIGNER_SIGNATURE_INFO*,
        void*,
        LPCWSTR,
        void*,
        void*,
        SIGNER_CONTEXT**);
    using SignerFreeSignerContextFunction = HRESULT(WINAPI*)(SIGNER_CONTEXT*);

    constexpr DWORD kSignerSubjectFile = 1;
    constexpr DWORD kSignerCertStore = 2;
    constexpr DWORD kSignerNoAttr = 0;
    constexpr DWORD kSignerCertPolicyChainNoRoot = 8;

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

    struct CryptMessageDeleter
    {
        void operator()(void* message) const
        {
            if (message != nullptr)
            {
                CryptMsgClose(reinterpret_cast<HCRYPTMSG>(message));
            }
        }
    };

    using UniqueCertContext = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
    using UniqueCertStore = std::unique_ptr<void, CertStoreDeleter>;
    using UniqueCryptMessage = std::unique_ptr<void, CryptMessageDeleter>;

    [[noreturn]] void ThrowLastError(const std::string& message)
    {
        throw std::runtime_error(message + " (Win32 error " + std::to_string(GetLastError()) + ")");
    }

    [[noreturn]] void ThrowHRESULT(const std::string& message, const HRESULT hr)
    {
        throw std::runtime_error(
            message + " (HRESULT " + std::to_string(static_cast<unsigned long>(hr)) + ")");
    }

    ALG_ID ParseDigestAlgorithm(const std::wstring& digest_algorithm)
    {
        if (_wcsicmp(digest_algorithm.c_str(), L"sha256") == 0)
        {
            return CALG_SHA_256;
        }

        throw std::runtime_error("Unsupported file digest algorithm.");
    }

    UniqueCertStore OpenPersonalStore()
    {
        HCERTSTORE store =
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
        if (store == nullptr)
        {
            ThrowLastError("Failed to open the CurrentUser\\My certificate store");
        }

        return UniqueCertStore(store);
    }

    UniqueCertContext
    FindCertificateBySubject(const HCERTSTORE store, const std::wstring& subject_name)
    {
        PCCERT_CONTEXT certificate = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_W,
            subject_name.c_str(),
            nullptr);
        if (certificate == nullptr)
        {
            throw std::runtime_error(
                "Could not find a matching signing certificate by subject name.");
        }

        return UniqueCertContext(certificate);
    }

    void EnsurePrivateKeyIsAvailable(const CERT_CONTEXT* certificate)
    {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle = 0;
        DWORD key_spec = 0;
        BOOL must_free = FALSE;
        if (!CryptAcquireCertificatePrivateKey(
                certificate,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                nullptr,
                &key_handle,
                &key_spec,
                &must_free))
        {
            ThrowLastError("The selected certificate does not have an accessible private key");
        }

        if (must_free != FALSE)
        {
            if (key_spec == CERT_NCRYPT_KEY_SPEC)
            {
                NCryptFreeObject(key_handle);
            }
            else
            {
                CryptReleaseContext(static_cast<HCRYPTPROV>(key_handle), 0);
            }
        }
    }

    struct QueriedCertificateStore
    {
        DWORD content_type = 0;
        UniqueCertStore store;
        UniqueCryptMessage message;
        UniqueCertContext single_certificate;
    };

    QueriedCertificateStore QueryCertificateStore(const std::filesystem::path& path)
    {
        DWORD encoding = 0;
        DWORD content = 0;
        DWORD format = 0;
        HCERTSTORE store = nullptr;
        HCRYPTMSG message = nullptr;
        const CERT_CONTEXT* queried_certificate = nullptr;

        if (!CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.c_str(),
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                &encoding,
                &content,
                &format,
                &store,
                &message,
                reinterpret_cast<const void**>(&queried_certificate)))
        {
            ThrowLastError("Failed to open the certificate source");
        }

        return QueriedCertificateStore{
            content,
            UniqueCertStore(store),
            UniqueCryptMessage(message),
            UniqueCertContext(
                content == CERT_QUERY_CONTENT_CERT || content == CERT_QUERY_CONTENT_SERIALIZED_CERT
                    ? queried_certificate
                    : nullptr),
        };
    }

    UniqueCertContext DuplicateCertificate(const CERT_CONTEXT* certificate)
    {
        if (certificate == nullptr)
        {
            throw std::runtime_error("Certificate source does not contain a certificate.");
        }

        return UniqueCertContext(CertDuplicateCertificateContext(certificate));
    }

    UniqueCertContext FirstCertificateFromStore(const QueriedCertificateStore& queried_store)
    {
        if (queried_store.store)
        {
            const CERT_CONTEXT* first = CertEnumCertificatesInStore(
                reinterpret_cast<HCERTSTORE>(queried_store.store.get()), nullptr);
            if (first != nullptr)
            {
                auto duplicate = DuplicateCertificate(first);
                CertFreeCertificateContext(first);
                return duplicate;
            }
        }

        if (queried_store.single_certificate)
        {
            return DuplicateCertificate(queried_store.single_certificate.get());
        }

        throw std::runtime_error("Certificate source is empty.");
    }

    void WriteCertificateFile(const std::filesystem::path& path, const CERT_CONTEXT* certificate)
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output.is_open())
        {
            throw std::runtime_error("Failed to create the output certificate file.");
        }

        output.write(
            reinterpret_cast<const char*>(certificate->pbCertEncoded),
            static_cast<std::streamsize>(certificate->cbCertEncoded));
        if (!output.good())
        {
            throw std::runtime_error("Failed to write the output certificate file.");
        }
    }

    class WindowsCryptoBackend final : public ICryptoBackend
    {
    public:
        void SignFile(const SignRequest& request) override
        {
            auto store = OpenPersonalStore();
            auto certificate = FindCertificateBySubject(
                reinterpret_cast<HCERTSTORE>(store.get()), request.subject_name);
            EnsurePrivateKeyIsAvailable(certificate.get());

            wil::unique_hmodule mssign32(LoadLibraryW(L"Mssign32.dll"));
            if (!mssign32)
            {
                ThrowLastError("Failed to load Mssign32.dll");
            }

            const auto signer_sign_ex = reinterpret_cast<SignerSignExFunction>(
                GetProcAddress(mssign32.get(), "SignerSignEx"));
            const auto signer_free_context = reinterpret_cast<SignerFreeSignerContextFunction>(
                GetProcAddress(mssign32.get(), "SignerFreeSignerContext"));
            if (signer_sign_ex == nullptr || signer_free_context == nullptr)
            {
                throw std::runtime_error("Failed to resolve SignerSignEx exports.");
            }

            DWORD subject_index = 0;
            SIGNER_FILE_INFO file_info{
                sizeof(file_info),
                request.file_path.c_str(),
                nullptr,
            };
            SIGNER_SUBJECT_INFO subject_info{
                sizeof(subject_info),
                &subject_index,
                kSignerSubjectFile,
                {.pSignerFileInfo = &file_info},
            };
            SIGNER_CERT_STORE_INFO store_info{
                sizeof(store_info),
                certificate.get(),
                kSignerCertPolicyChainNoRoot,
                reinterpret_cast<HCERTSTORE>(store.get()),
            };
            SIGNER_CERT signer_certificate{
                sizeof(signer_certificate),
                kSignerCertStore,
                {.pCertStoreInfo = &store_info},
                nullptr,
            };
            SIGNER_SIGNATURE_INFO signature_info{
                sizeof(signature_info),
                ParseDigestAlgorithm(request.file_digest_algorithm),
                kSignerNoAttr,
                nullptr,
                nullptr,
                nullptr,
            };
            SIGNER_CONTEXT* signer_context = nullptr;
            const HRESULT hr = signer_sign_ex(
                0,
                &subject_info,
                &signer_certificate,
                &signature_info,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                &signer_context);
            if (signer_context != nullptr)
            {
                (void)signer_free_context(signer_context);
            }
            if (FAILED(hr))
            {
                ThrowHRESULT("Failed to sign the PE file", hr);
            }
        }

        void ExportCertificate(const ExportCertificateRequest& request) override
        {
            const auto queried_store = QueryCertificateStore(request.source_store_path);
            const auto certificate = FirstCertificateFromStore(queried_store);
            WriteCertificateFile(request.output_certificate_path, certificate.get());
        }
    };

} // namespace

std::unique_ptr<ICryptoBackend> CreatePlatformBackend()
{
    return std::make_unique<WindowsCryptoBackend>();
}

} // namespace ccky
