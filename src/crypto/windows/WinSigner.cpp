#include "crypto/AuthenticodeSigner.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include <windows.h>

#include <mscat.h>
#include <ncrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include "crypto/windows/WinCert.h"
#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WindowsException.h"

#ifndef SIGNER_SUBJECT_FILE
#define SIGNER_SUBJECT_FILE 1
#endif

#ifndef SIGNER_CERT_STORE
#define SIGNER_CERT_STORE 2
#endif

#ifndef SIGNER_CERT_POLICY_CHAIN
#define SIGNER_CERT_POLICY_CHAIN 2
#endif

namespace ccky
{
namespace crypto
{

typedef struct _SIGNER_FILE_INFO
{
    DWORD cbSize;
    LPCWSTR pwszFileName;
    HANDLE hFile;
} SIGNER_FILE_INFO, *PSIGNER_FILE_INFO;

typedef struct _SIGNER_SUBJECT_INFO
{
    DWORD cbSize;
    DWORD* pdwIndex;
    DWORD dwSubjectChoice;
    union
    {
        SIGNER_FILE_INFO* pSignerFileInfo;
    };
} SIGNER_SUBJECT_INFO, *PSIGNER_SUBJECT_INFO;

typedef struct _SIGNER_CERT_STORE_INFO
{
    DWORD cbSize;
    PCCERT_CONTEXT pSigningCert;
    DWORD dwCertPolicy;
    HCERTSTORE hCertStore;
} SIGNER_CERT_STORE_INFO, *PSIGNER_CERT_STORE_INFO;

typedef struct _SIGNER_CERT
{
    DWORD cbSize;
    DWORD dwCertChoice;
    union
    {
        LPCWSTR pwszSpcFile;
        SIGNER_CERT_STORE_INFO* pCertStoreInfo;
    };
    HWND hwnd;
} SIGNER_CERT, *PSIGNER_CERT;

typedef struct _SIGNER_ATTR_AUTHCODE
{
    DWORD cbSize;
    BOOL fCommercial;
    BOOL fIndividual;
    LPCWSTR pwszName;
    LPCWSTR pwszInfo;
} SIGNER_ATTR_AUTHCODE, *PSIGNER_ATTR_AUTHCODE;

typedef struct _SIGNER_SIGNATURE_INFO
{
    DWORD cbSize;
    ALG_ID algidHash;
    DWORD dwAttrChoice;
    union
    {
        SIGNER_ATTR_AUTHCODE* pAttrAuthcode;
    };
    PCRYPT_ATTRIBUTES psAuthenticated;
    PCRYPT_ATTRIBUTES psUnauthenticated;
} SIGNER_SIGNATURE_INFO, *PSIGNER_SIGNATURE_INFO;

typedef HRESULT(WINAPI* SignerSignEx_t)(DWORD dwFlags, SIGNER_SUBJECT_INFO* pSubjectInfo,
    SIGNER_CERT* pSignerCert, SIGNER_SIGNATURE_INFO* pSignatureInfo, LPVOID pProviderInfo,
    LPCWSTR pwszHttpTimeStamp, PCRYPT_ATTRIBUTES psRequest, LPVOID pSipData,
    LPVOID ppSignerContext);

typedef HRESULT(WINAPI* SignerTimeStampEx_t)(DWORD dwFlags, SIGNER_SUBJECT_INFO* pSubjectInfo,
    LPCWSTR pwszHttpTimeStamp, PCRYPT_ATTRIBUTES psRequest, LPVOID pSipData,
    LPVOID ppSignerContext);

class MSSign32Loader
{
  public:
    static MSSign32Loader& getInstance()
    {
        static MSSign32Loader s_instance;
        return s_instance;
    }

    SignerSignEx_t SignerSignEx = nullptr;
    SignerTimeStampEx_t SignerTimeStampEx = nullptr;

  private:
    MSSign32Loader()
    {
        HMODULE hMod = LoadLibraryA("mssign32.dll");
        if (hMod)
        {
            SignerSignEx = reinterpret_cast<SignerSignEx_t>(GetProcAddress(hMod, "SignerSignEx"));
            SignerTimeStampEx =
                reinterpret_cast<SignerTimeStampEx_t>(GetProcAddress(hMod, "SignerTimeStampEx"));
        }
    }
};

void AuthenticodeSigner::sign(
    CertificatePtr cert, const SignOptions& options, const std::string& peFilePath)
{
    auto& loader = MSSign32Loader::getInstance();
    if (!loader.SignerSignEx)
    {
        throw WindowsException(
            "mssign32.dll or SignerSignEx is not available on this Windows system.", false);
    }

    auto* winCert = dynamic_cast<WinCert*>(cert.get());
    if (!winCert || !winCert->getInternal())
    {
        throw WindowsException("Invalid or missing signing certificate.", false);
    }
    PCCERT_CONTEXT pCert = winCert->getInternal();

    std::wstring wFileName = WinHelper::utf8ToWide(peFilePath);
    std::wstring wTimestamp;
    if (!options.timestampUrl.empty())
    {
        wTimestamp = WinHelper::utf8ToWide(options.timestampUrl);
    }

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            pCert, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, nullptr, &hKey, &dwKeySpec, &fFree))
    {
        throw WindowsException("Failed to acquire certificate private key.", false);
    }

    if (fFree)
    {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(hKey);
        }
        else
        {
            CryptReleaseContext(hKey, 0);
        }
    }

    SIGNER_FILE_INFO fileInfo = {
        .cbSize = sizeof(SIGNER_FILE_INFO),
        .pwszFileName = wFileName.c_str(),
        .hFile = nullptr,
    };
    DWORD dwIndex = 0;

    SIGNER_SUBJECT_INFO subjectInfo = {
        .cbSize = sizeof(SIGNER_SUBJECT_INFO),
        .pdwIndex = &dwIndex,
        .dwSubjectChoice = SIGNER_SUBJECT_FILE,
        .pSignerFileInfo = &fileInfo,
    };

    SIGNER_CERT_STORE_INFO certStoreInfo = {
        .cbSize = sizeof(SIGNER_CERT_STORE_INFO),
        .pSigningCert = pCert,
        .dwCertPolicy = SIGNER_CERT_POLICY_CHAIN,
        .hCertStore = pCert->hCertStore,
    };

    SIGNER_CERT signerCert = {
        .cbSize = sizeof(SIGNER_CERT),
        .dwCertChoice = SIGNER_CERT_STORE,
        .pCertStoreInfo = &certStoreInfo,
        .hwnd = nullptr,
    };

    ALG_ID algId = CALG_SHA1;
    if (options.fileDigestAlg == "SHA256" || options.fileDigestAlg == "sha256")
    {
        algId = CALG_SHA_256;
    }

    SIGNER_SIGNATURE_INFO sigInfo = {
        .cbSize = sizeof(SIGNER_SIGNATURE_INFO),
        .algidHash = algId,
        .dwAttrChoice = 0,
        .pAttrAuthcode = nullptr,
        .psAuthenticated = nullptr,
        .psUnauthenticated = nullptr,
    };

    HRESULT hr = loader.SignerSignEx(0, &subjectInfo, &signerCert, &sigInfo, nullptr,
        wTimestamp.empty() ? nullptr : wTimestamp.c_str(), nullptr, nullptr, nullptr);

    if (hr != S_OK)
    {
        Win32Check::checkHr(hr, "SignerSignEx failed");
    }
}

void AuthenticodeSigner::verify(const VerifyOptions& options, const std::string& peFilePath)
{
    std::wstring wPath = WinHelper::utf8ToWide(peFilePath);
    WINTRUST_FILE_INFO fileInfo = {
        .cbStruct = sizeof(WINTRUST_FILE_INFO),
        .pcwszFilePath = wPath.c_str(),
        .hFile = nullptr,
        .pgKnownSubject = nullptr,
    };

    std::wstring wCat;
    WINTRUST_CATALOG_INFO catInfo = {
        .cbStruct = sizeof(WINTRUST_CATALOG_INFO),
        .dwCatalogVersion = 0,
        .pcwszCatalogFilePath = nullptr,
        .pcwszMemberTag = nullptr,
        .pcwszMemberFilePath = nullptr,
        .hMemberFile = nullptr,
        .pbCalculatedFileHash = nullptr,
        .cbCalculatedFileHash = 0,
        .pcCatalogContext = nullptr,
    };
    if (!options.catalogFile.empty())
    {
        wCat = WinHelper::utf8ToWide(options.catalogFile);
        catInfo.pcwszCatalogFilePath = wCat.c_str();
        catInfo.pcwszMemberFilePath = wPath.c_str();
    }

    WINTRUST_DATA wintrustData = {
        .cbStruct = sizeof(WINTRUST_DATA),
        .pPolicyCallbackData = nullptr,
        .pSIPClientData = nullptr,
        .dwUIChoice = WTD_UI_NONE,
        .fdwRevocationChecks = WTD_REVOKE_NONE,
        .dwUnionChoice =
            static_cast<DWORD>(options.catalogFile.empty() ? WTD_CHOICE_FILE : WTD_CHOICE_CATALOG),
        .pFile = options.catalogFile.empty() ? &fileInfo : nullptr,
        .dwStateAction = WTD_STATEACTION_IGNORE,
        .hWVTStateData = nullptr,
        .pwszURLReference = nullptr,
        .dwProvFlags = 0,
        .dwUIContext = 0,
    };
    if (!options.catalogFile.empty())
    {
        wintrustData.pCatalog = &catInfo;
    }

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    if (options.kernelDriverPolicy)
    {
        GUID driverGUID = {
            0xf750e6c3,
            0x38ee,
            0x11d1,
            {0x85, 0xe5, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
        };
        policyGUID = driverGUID;
    }

    LONG res = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGUID, &wintrustData);
    if (res == 0)
    {
        return;
    }
    else if (res == static_cast<LONG>(CERT_E_UNTRUSTEDROOT) || res == -2146762487)
    {
        throw WindowsException(
            "A certificate chain processed, but terminated in a root\n\tcertificate which is not "
            "trusted by the trust provider.",
            false);
    }
    else if (res == static_cast<LONG>(TRUST_E_NOSIGNATURE) || res == -2146762749)
    {
        throw WindowsException("No signature found.", false);
    }
    else
    {
        Win32Check::checkHr(res, "WinVerifyTrust failed on " + peFilePath);
    }
}

void AuthenticodeSigner::timestamp(const TimestampOptions& options, const std::string& peFilePath)
{
    auto& loader = MSSign32Loader::getInstance();
    if (!loader.SignerTimeStampEx)
    {
        throw WindowsException(
            "mssign32.dll or SignerTimeStampEx is not available on this Windows system.", false);
    }

    std::wstring wFileName = WinHelper::utf8ToWide(peFilePath);
    std::wstring wTimestamp = WinHelper::utf8ToWide(options.timestampUrl);

    SIGNER_FILE_INFO fileInfo = {
        .cbSize = sizeof(SIGNER_FILE_INFO),
        .pwszFileName = wFileName.c_str(),
        .hFile = nullptr,
    };
    DWORD dwIndex = 0;
    SIGNER_SUBJECT_INFO subjectInfo = {
        .cbSize = sizeof(SIGNER_SUBJECT_INFO),
        .pdwIndex = &dwIndex,
        .dwSubjectChoice = SIGNER_SUBJECT_FILE,
        .pSignerFileInfo = &fileInfo,
    };

    HRESULT hr =
        loader.SignerTimeStampEx(0, &subjectInfo, wTimestamp.c_str(), nullptr, nullptr, nullptr);
    if (hr != S_OK)
    {
        Win32Check::checkHr(hr, "SignerTimeStampEx failed");
    }
}

void AuthenticodeSigner::catdb(const CatdbOptions& options)
{
    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0))
    {
        throw WindowsException("Failed to acquire catalog admin context.", false);
    }

    for (const auto& file : options.files)
    {
        std::wstring wFile = WinHelper::utf8ToWide(file);
        if (options.remove)
        {
            if (!CryptCATAdminRemoveCatalog(hCatAdmin, wFile.c_str(), 0))
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                throw WindowsException("Failed to remove catalog " + file, false);
            }
        }
        else
        {
            HCATINFO hCatInfo =
                CryptCATAdminAddCatalog(hCatAdmin, const_cast<PWSTR>(wFile.c_str()), nullptr, 0);
            if (!hCatInfo)
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                throw WindowsException("Failed to add catalog " + file, false);
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
}

} // namespace crypto
} // namespace ccky
