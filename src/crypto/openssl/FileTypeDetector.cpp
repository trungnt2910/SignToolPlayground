#include "crypto/FileTypeDetector.h"

#include <openssl/bio.h>
#include <openssl/pkcs12.h>

#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

StoreType FileTypeDetector::detectCertType(const std::string& filePath)
{
    BIOPtr bio(BIO_new_file(filePath.c_str(), "rb"));
    if (bio)
    {
        PKCS12Ptr p12(d2i_PKCS12_bio(bio.get(), nullptr));
        if (p12)
        {
            return StoreType::PfxFile;
        }
    }

    return StoreType::CerFile;
}

} // namespace crypto
} // namespace ccky
