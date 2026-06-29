#include "crypto/Pvk2PfxConverter.h"

#include <filesystem>
#include <stdexcept>
#include <vector>

#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"
#include "crypto/ICertStore.h"
#include "crypto/PvkKey.h"
#include "crypto/openssl/OpenSslCert.h"
#include "crypto/openssl/OpenSslWrapper.h"
#include "crypto/openssl/PvkHelper.h"

namespace ccky
{
namespace crypto
{

void Pvk2PfxConverter::convert(const Pvk2PfxOptions& opts)
{
    if (opts.pvkFile.empty() || opts.spcFile.empty())
    {
        throw FileNotFoundException("PVK or SPC file not specified");
    }

    if (!std::filesystem::exists(opts.pvkFile))
    {
        throw FileNotFoundException("PVK file not found: " + opts.pvkFile);
    }

    if (!std::filesystem::exists(opts.spcFile))
    {
        throw FileNotFoundException("SPC file not found: " + opts.spcFile);
    }

    std::string outPfx = opts.pfxFile;
    if (outPfx.empty())
    {
        std::filesystem::path spcPath(opts.spcFile);
        outPfx = spcPath.replace_extension(".pfx").string();
    }

    if (!opts.force && std::filesystem::exists(outPfx))
    {
        throw OutputFileExistsException("Output PFX file exists: " + outPfx);
    }

    PvkKey pvkKey;
    pvkKey.load(opts.pvkFile);
    pvkKey.decrypt(opts.pvkPassword);

    EVPPKeyPtr pkey = PvkHelper::blobToPkey(pvkKey.getKeyData());

    auto store = CryptoFactory::createStore(StoreType::CerFile, opts.spcFile);
    if (!store)
    {
        throw FileNotFoundException("Failed to open SPC file: " + opts.spcFile);
    }

    try
    {
        store->load(opts.spcFile);
    }
    catch (...)
    {
        throw CckyCryptoException("Failed to load SPC file: " + opts.spcFile);
    }

    auto certs = store->getCertificates();
    if (certs.empty())
    {
        throw CckyCryptoException("No certificates found in SPC file: " + opts.spcFile);
    }

    auto mainCert = std::dynamic_pointer_cast<OpenSslCert>(certs[0]);
    if (!mainCert)
    {
        throw CckyCryptoException("Failed to parse main certificate from SPC file");
    }

    if (X509_check_private_key(mainCert->getInternal(), pkey.get()) != 1)
    {
        throw KeyMismatchException("Private key does not match certificate");
    }

    STACK_OF(X509)* caCerts = nullptr;
    if (certs.size() > 1)
    {
        caCerts = sk_X509_new_null();
        for (size_t i = 1; i < certs.size(); ++i)
        {
            auto caCert = std::dynamic_pointer_cast<OpenSslCert>(certs[i]);
            if (caCert)
            {
                sk_X509_push(caCerts, caCert->getInternal());
            }
        }
    }

    const char* pfxPass = opts.pfxPassword.empty() ? nullptr : opts.pfxPassword.c_str();

    PKCS12Ptr p12(PKCS12_create(const_cast<char*>(pfxPass), nullptr, pkey.get(),
        mainCert->getInternal(), caCerts, 0, 0, PKCS12_DEFAULT_ITER, 1, 0));

    if (caCerts)
    {
        sk_X509_free(caCerts);
    }

    if (!p12)
    {
        throw CckyCryptoException("Failed to create PKCS12 structure");
    }

    BIOPtr outBio(BIO_new_file(outPfx.c_str(), "wb"));
    if (!outBio)
    {
        throw CckyCryptoException("Failed to open output PFX file for writing: " + outPfx);
    }

    if (i2d_PKCS12_bio(outBio.get(), p12.get()) != 1)
    {
        throw CckyCryptoException("Failed to write PKCS12 to file");
    }
}

} // namespace crypto
} // namespace ccky
