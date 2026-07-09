#include "crypto/FileTypeDetector.h"

#include <windows.h>

#include <wincrypt.h>

#include "crypto/windows/Win32Helper.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

StoreType FileTypeDetector::detectCertType(const std::string& filePath)
{
    std::wstring wLocation = Win32Helper::utf8ToWide(filePath);
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    CertStorePtr hStore;
    CryptMsgPtr hMsg;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wLocation.c_str(), CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType, &dwFormatType,
            &hStore.init(), &hMsg.init(), nullptr))
    {
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
