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
    if (bio != nullptr)
    {
        PKCS12Ptr p12(d2i_PKCS12_bio(bio.get(), nullptr));
        if (p12 != nullptr)
        {
            return StoreType::PfxFile;
        }

        BIO_reset(bio.get());
        PKCS7Ptr p7(PEM_read_bio_PKCS7(bio.get(), nullptr, nullptr, nullptr));
        if (p7 == nullptr)
        {
            BIO_reset(bio.get());
            p7.reset(d2i_PKCS7_bio(bio.get(), nullptr));
        }
        if (p7 != nullptr)
        {
            return StoreType::P7bFile;
        }
    }

    return StoreType::CerFile;
}

} // namespace crypto
} // namespace ccky
