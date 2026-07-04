#include "crypto/FileTypeDetector.h"

#include <windows.h>

#include <wincrypt.h>

#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WinWrapper.h"

namespace ccky
{
namespace crypto
{

StoreType FileTypeDetector::detectCertType(const std::string& filePath)
{
    std::wstring wLocation = WinHelper::utf8ToWide(filePath);
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE rawStore = nullptr;
    HCRYPTMSG rawMsg = nullptr;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wLocation.c_str(), CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType, &dwFormatType, &rawStore,
            &rawMsg, nullptr))
    {
        CertStorePtr hStore(rawStore);
        CryptMsgPtr hMsg(rawMsg);
        switch (dwContentType)
        {
        case CERT_QUERY_CONTENT_PFX:
            return StoreType::PfxFile;
        case CERT_QUERY_CONTENT_PKCS7_SIGNED:
        case CERT_QUERY_CONTENT_PKCS7_UNSIGNED:
        case CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED:
            return StoreType::P7bFile;
        default:
            break;
        }
    }

    return StoreType::CerFile;
}

} // namespace crypto
} // namespace ccky
