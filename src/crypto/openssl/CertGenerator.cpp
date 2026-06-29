#include "crypto/CertGenerator.h"

#include <filesystem>
#include <stdexcept>
#include <string>

#include <openssl/asn1t.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"
#include "crypto/ICertStore.h"
#include "crypto/PvkKey.h"
#include "crypto/openssl/OpenSslCert.h"
#include "crypto/openssl/OpenSslPrivateKey.h"
#include "crypto/openssl/OpenSslWrapper.h"
#include "crypto/openssl/PvkHelper.h"
#include "crypto/openssl/SpcStructures.h"
#include "crypto/openssl/X509NameParser.h"

#define OID_SPC_COMMERCIAL_SP_KEY_PURPOSE "1.3.6.1.4.1.311.2.1.22"
#define OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE "1.3.6.1.4.1.311.2.1.21"

namespace ccky
{
namespace crypto
{

namespace
{
crypto::X509Ptr loadIssuerCert(const MakeCertOptions& options)
{
    if (!options.hasIssuerCert || options.issuerCertFile.empty())
    {
        return nullptr;
    }
    try
    {
        auto issuerStore = CryptoFactory::createStore(StoreType::CerFile, options.issuerCertFile);
        issuerStore->load(options.issuerCertFile);
        auto certs = issuerStore->getCertificates();
        if (certs.empty())
        {
            throw std::runtime_error("No certificates found in issuer file");
        }
        auto issuerCert = std::dynamic_pointer_cast<OpenSslCert>(certs[0]);
        if (!issuerCert)
        {
            throw std::runtime_error("Failed to cast issuer certificate");
        }
        X509* raw = issuerCert->getInternal();
        X509_up_ref(raw);
        return crypto::X509Ptr(raw);
    }
    catch (const std::exception& e)
    {
        throw crypto::CckyException(
            "Can't access the certificate of the issuer ('" + options.issuerCertFile + "')", false);
    }
}

crypto::EVPPKeyPtr loadIssuerKey(const MakeCertOptions& options)
{
    if (!options.hasIssuerCert)
    {
        return nullptr;
    }
    if (options.issuerPvkFile.empty())
    {
        throw crypto::CckyException(
            "Issuer private key file (-iv) is required on this platform.", false);
    }

    crypto::PvkKey issuerPvk;
    try
    {
        issuerPvk.load(options.issuerPvkFile);
    }
    catch (...)
    {
        throw crypto::CckyException(
            "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
    }

    std::string password;
    if (issuerPvk.isEncrypted() && options.openIssuerPasswordCallback)
    {
        password = options.openIssuerPasswordCallback();
    }
    if (issuerPvk.isEncrypted())
    {
        try
        {
            issuerPvk.decrypt(password);
        }
        catch (const crypto::PvkIncorrectPasswordException&)
        {
            throw crypto::CckyException(
                "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
        }
    }

    if (issuerPvk.getKeyType() != options.issuerKeySpec)
    {
        throw crypto::CckyException(
            "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
    }

    try
    {
        return crypto::PvkHelper::blobToPkey(issuerPvk.getKeyData());
    }
    catch (...)
    {
        throw crypto::CckyException(
            "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
    }
}

PrivateKeyPtr loadSubjectKeyFromCert(const MakeCertOptions& options)
{
    BIO* bio = BIO_new_file(options.subjectCertFile.c_str(), "rb");
    if (!bio)
    {
        throw crypto::CckyException(
            "Can't access the certificate of the subject ('" + options.subjectCertFile + "')",
            false);
    }
    crypto::BIOPtr bioSafe(bio);
    X509* rawSubjCert = d2i_X509_bio(bioSafe.get(), nullptr);
    if (!rawSubjCert)
    {
        throw crypto::CckyException(
            "Can't access the certificate of the subject ('" + options.subjectCertFile + "')",
            false);
    }
    crypto::X509Ptr subjCertSafe(rawSubjCert);

    EVP_PKEY* raw_pkey = X509_get_pubkey(subjCertSafe.get());
    if (!raw_pkey)
    {
        throw crypto::CckyException(
            "Can't access the certificate of the subject ('" + options.subjectCertFile + "')",
            false);
    }
    return std::make_shared<crypto::OpenSslPrivateKey>(crypto::EVPPKeyPtr(raw_pkey));
}

PrivateKeyPtr loadSubjectKeyFromPvk(const MakeCertOptions& options)
{
    crypto::PvkKey pvk;
    pvk.load(options.pvkFile);
    std::string password;
    if (pvk.isEncrypted() && options.openPasswordCallback)
    {
        password = options.openPasswordCallback();
    }

    if (pvk.isEncrypted())
    {
        try
        {
            pvk.decrypt(password);
        }
        catch (const crypto::PvkIncorrectPasswordException&)
        {
            throw crypto::CckyException(
                "Can't create the key of the subject ('" + options.pvkFile + "')", false);
        }
    }
    if (pvk.getKeyType() != options.keySpec)
    {
        throw crypto::CckyException(
            "Can't create the key of the subject ('" + options.pvkFile + "')", false);
    }
    auto pkey = crypto::PvkHelper::blobToPkey(pvk.getKeyData());
    return std::make_shared<crypto::OpenSslPrivateKey>(std::move(pkey));
}

void saveSubjectKeyToPvk(
    const crypto::EVPPKeyPtr& pkey, const MakeCertOptions& options, const std::string& password)
{
    crypto::PvkKey pvk;
    std::vector<uint8_t> blob = crypto::PvkHelper::pkeyToBlob(pkey.get(), options.keySpec);
    pvk.setKeyData(blob, options.keySpec);
    if (!password.empty())
    {
        pvk.encrypt(password);
    }
    pvk.save(options.pvkFile);
}

crypto::X509Ptr createUnsignedCertificate(const MakeCertOptions& options,
    const crypto::EVPPKeyPtr& subjectKey, const crypto::X509Ptr& issuerCert)
{
    crypto::X509Ptr cert(X509_new());
    X509_set_version(cert.get(), 2); // X509v3

    // Set serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert.get());
    if (options.hasSerialNum)
    {
        ASN1_INTEGER_set(serial, options.serialNum);
    }
    else
    {
        long randSerial = 0;
        do
        {
            CryptoFactory::getRandomBytes(&randSerial, sizeof(randSerial));
            randSerial &= 0x7FFFFFFF; // Ensure it is positive and fits in 31 bits
        } while (randSerial == 0);
        ASN1_INTEGER_set(serial, randSerial);
    }

    // Set subject name
    X509_NAME* name = X509_get_subject_name(cert.get());
    ParsedX509Name parsedName = X509NameParser::parse(options.subjectName);
    for (size_t i = 0; i < parsedName.size(); ++i)
    {
        const auto& rdn = parsedName[i];
        for (size_t j = 0; j < rdn.size(); ++j)
        {
            const auto& attr = rdn[j];
            int set = (j == 0) ? -1 : 0;
            if (!X509_NAME_add_entry_by_txt(name, attr.key.c_str(), MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(attr.value.c_str()), -1, -1, set))
            {
                throw crypto::CckyException(
                    "Failed to add name entry: " + attr.key + "=" + attr.value, false);
            }
        }
    }

    // Set issuer name
    if (options.selfSigned || !options.hasIssuerCert || !issuerCert)
    {
        X509_set_issuer_name(cert.get(), name);
    }
    else
    {
        X509_set_issuer_name(cert.get(), X509_get_subject_name(issuerCert.get()));
    }

    // Set validity
    ASN1_TIME* notBefore = X509_getm_notBefore(cert.get());
    ASN1_TIME* notAfter = X509_getm_notAfter(cert.get());

    X509_gmtime_adj(notBefore, 0);

    if (!options.endStr.empty())
    {
        int m, d, y;
        if (std::sscanf(options.endStr.c_str(), "%d/%d/%d", &m, &d, &y) == 3)
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%04d%02d%02d000000Z", y, m, d);
            ASN1_TIME_set_string(notAfter, buf);
        }
        else
        {
            ASN1_TIME_set_string(notAfter, "20391231235959Z");
        }
    }
    else if (options.months > 0)
    {
        X509_gmtime_adj(notAfter, options.months * 30 * 24 * 3600);
    }
    else
    {
        // Default to exactly 12/31/2039 23:59:59 GMT as per MS docs.
        ASN1_TIME_set_string(notAfter, "20391231235959Z");
    }

    X509_set_pubkey(cert.get(), subjectKey.get());
    return cert;
}

void addBasicConstraints(X509* cert, const MakeCertOptions& options)
{
    std::string value;
    if (options.cyCertType == "authority")
    {
        value = "CA:TRUE";
        if (options.hasPathLen)
        {
            value += ",pathlen:" + std::to_string(options.pathLen);
        }
    }
    else
    {
        value = "CA:FALSE,pathlen:0";
    }

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509ExtensionPtr ext(X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, value.c_str()));
    if (!ext)
    {
        throw std::runtime_error("Failed to create basic constraints extension");
    }
    X509_EXTENSION_set_critical(ext.get(), 1);

    if (!X509_add_ext(cert, ext.get(), -1))
    {
        throw std::runtime_error("Failed to add basic constraints extension");
    }
}

void addEku(X509* cert, const MakeCertOptions& options)
{
    std::vector<std::string> allEkuOids = options.ekuOids;
    if (options.authority == "commercial")
    {
        allEkuOids.push_back(OID_SPC_COMMERCIAL_SP_KEY_PURPOSE);
    }
    else if (options.authority == "individual")
    {
        allEkuOids.push_back(OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE);
    }

    if (!allEkuOids.empty())
    {
        EKUPtr eku(sk_ASN1_OBJECT_new_null());
        for (const auto& oid : allEkuOids)
        {
            ASN1ObjectPtr obj(OBJ_txt2obj(oid.c_str(), 1));
            if (!obj)
            {
                throw std::runtime_error("Invalid EKU OID: " + oid);
            }
            if (sk_ASN1_OBJECT_push(eku.get(), obj.get()) > 0)
            {
                obj.release();
            }
        }
        X509_add1_ext_i2d(cert, NID_ext_key_usage, eku.get(), 0, 0);
    }
}

void addPolicyLink(X509* cert, const MakeCertOptions& options)
{
    if (options.policyLink.empty())
    {
        return;
    }

    SpcSpAgencyInfoPtr info(SPC_SP_AGENCY_INFO_new());
    if (!info)
    {
        throw std::runtime_error("Failed to create SPC_SP_AGENCY_INFO");
    }

    info->policyInformation = ASN1_IA5STRING_new();
    if (!info->policyInformation)
    {
        throw std::runtime_error("Failed to create ASN1_IA5STRING");
    }

    ASN1_STRING_set(info->policyInformation,
        reinterpret_cast<const unsigned char*>(options.policyLink.data()),
        options.policyLink.size());

    ASN1ObjectPtr obj(OBJ_txt2obj(OID_SPC_SP_AGENCY_INFO, 1));
    if (!obj)
    {
        throw std::runtime_error("Failed to create OID for SpcSpAgencyInfo");
    }

    int len = i2d_SPC_SP_AGENCY_INFO(info.get(), nullptr);
    if (len <= 0)
    {
        unsigned long errCode = ERR_get_error();
        char buf[256];
        ERR_error_string_n(errCode, buf, sizeof(buf));
        throw std::runtime_error(
            std::string("Failed to encode SPC_SP_AGENCY_INFO. OpenSSL error: ") + buf);
    }
    std::vector<uint8_t> encoded(len);
    uint8_t* p = encoded.data();
    i2d_SPC_SP_AGENCY_INFO(info.get(), &p);

    ASN1OctetStringPtr octet(ASN1_OCTET_STRING_new());
    if (!octet || !ASN1_OCTET_STRING_set(octet.get(), encoded.data(), len))
    {
        throw std::runtime_error("Failed to create octet string for SpcSpAgencyInfo");
    }

    X509ExtensionPtr ext(X509_EXTENSION_create_by_OBJ(nullptr, obj.get(), 0, octet.get()));
    if (!ext || !X509_add_ext(cert, ext.get(), -1))
    {
        throw std::runtime_error("Failed to add SpcSpAgencyInfo extension");
    }
}

void addNetscape(X509* cert, const MakeCertOptions& options)
{
    if (!options.netscape)
    {
        return;
    }
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509ExtensionPtr ext(X509V3_EXT_conf_nid(nullptr, &ctx, NID_netscape_cert_type, "client"));
    if (ext)
    {
        X509_add_ext(cert, ext.get(), -1);
    }
}

void signCertificate(const crypto::X509Ptr& cert, const crypto::EVPPKeyPtr& subjectKey,
    const crypto::EVPPKeyPtr& issuerKey, const MakeCertOptions& options)
{
    const EVP_MD* md = EVP_get_digestbyname(options.algo.c_str());
    if (!md)
    {
        throw std::runtime_error("Unknown digest algorithm: " + options.algo);
    }

    EVP_PKEY* signKey = subjectKey.get();
    if (issuerKey)
    {
        signKey = issuerKey.get();
    }

    if (!X509_sign(cert.get(), signKey, md))
    {
        throw std::runtime_error("Failed to sign certificate");
    }
}

void writeCertificate(const crypto::X509Ptr& cert, const MakeCertOptions& options)
{
    if (!options.outputCertFile.empty())
    {
        crypto::BIOPtr bio_out(BIO_new_file(options.outputCertFile.c_str(), "w"));
        if (!bio_out)
        {
            throw std::runtime_error(
                "Failed to open output certificate file: " + options.outputCertFile);
        }
        if (!i2d_X509_bio(bio_out.get(), cert.get()))
        {
            throw std::runtime_error("Failed to write certificate");
        }
    }
}
} // namespace

PrivateKeyPtr CertGenerator::loadSubjectKey(const MakeCertOptions& options)
{
    if (!options.subjectCertFile.empty())
    {
        return loadSubjectKeyFromCert(options);
    }
    if (!options.pvkFile.empty())
    {
        return loadSubjectKeyFromPvk(options);
    }
    return nullptr;
}

PrivateKeyPtr CertGenerator::generateSubjectKey(const MakeCertOptions& options)
{
    if (!options.pvkFile.empty() && std::filesystem::exists(options.pvkFile))
    {
        throw crypto::CckyException(
            "Can't create the key of the subject ('" + options.pvkFile + "')", false);
    }

    // Validate provider type
    int providerType = options.syProviderType;
    if (providerType != 0 && providerType != 1 && providerType != 3 && providerType != 12 &&
        providerType != 13)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw crypto::CckyException(msg, false);
    }

    // Validate keySpec
    if (options.keySpec != 1 && options.keySpec != 2)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw crypto::CckyException(msg, false);
    }

    crypto::EVPPKeyPtr pkey(EVP_PKEY_new());
    int keySpec = options.keySpec;
    int keyLen = options.keyLen;
    if (keyLen == 0)
    {
        if (providerType == 3 || providerType == 13)
        {
            // OpenSSL 3.0 FFC parameter validation restricts DSA key sizes to at least 1024 bits.
            // Windows defaults to 512, but we must use 1024 here to avoid "bad ffc parameters"
            // error.
            keyLen = 1024;
        }
        else
        {
            keyLen = 2048;
        }
    }

    if (providerType == 3 || providerType == 13)
    {
        if (keySpec == 1) // AT_KEYEXCHANGE
        {
            if (providerType == 13)
            {
                EVP_PKEY* raw_pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "DH", (size_t)keyLen);
                if (!raw_pkey)
                {
                    throw std::runtime_error("Failed to generate DH key");
                }
                pkey.reset(raw_pkey);
            }
            else
            {
                throw crypto::CckyException("Can't create the key of the subject", false);
            }
        }
        else // AT_SIGNATURE
        {
            EVPPKeyCtxPtr pctx(EVP_PKEY_CTX_new_from_name(nullptr, "DSA", nullptr));
            if (!pctx || EVP_PKEY_paramgen_init(pctx.get()) <= 0)
            {
                throw std::runtime_error("Failed to initialize DSA parameter generation");
            }
            if (EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx.get(), (int)keyLen) <= 0)
            {
                throw std::runtime_error("Failed to set DSA parameter bits");
            }
            EVP_PKEY* raw_params = nullptr;
            if (EVP_PKEY_paramgen(pctx.get(), &raw_params) <= 0)
            {
                unsigned long errVal = ERR_get_error();
                char buf[256];
                ERR_error_string_n(errVal, buf, sizeof(buf));
                throw std::runtime_error(std::string("Failed to generate DSA parameters: ") + buf);
            }
            EVPPKeyPtr params(raw_params);

            EVPPKeyCtxPtr kctx(EVP_PKEY_CTX_new(params.get(), nullptr));
            EVP_PKEY* raw_pkey = nullptr;
            if (kctx)
            {
                if (EVP_PKEY_keygen_init(kctx.get()) <= 0 ||
                    EVP_PKEY_keygen(kctx.get(), &raw_pkey) <= 0)
                {
                    raw_pkey = nullptr;
                }
            }
            if (!raw_pkey)
            {
                unsigned long errVal = ERR_get_error();
                char buf[256];
                ERR_error_string_n(errVal, buf, sizeof(buf));
                throw std::runtime_error(std::string("Failed to generate DSA key: ") + buf);
            }
            pkey.reset(raw_pkey);
        }
    }
    else if (providerType == 0 || providerType == 1 || providerType == 24)
    {
        EVP_PKEY* raw_pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", (size_t)keyLen);
        if (!raw_pkey)
        {
            throw std::runtime_error("Failed to generate RSA key");
        }
        pkey.reset(raw_pkey);
    }
    else
    {
        throw crypto::CckyException("Can't create the key of the subject", false);
    }

    std::string password;
    if (!options.pvkFile.empty())
    {
        if (options.createPasswordCallback)
        {
            password = options.createPasswordCallback();
        }
        saveSubjectKeyToPvk(pkey, options, password);

        try
        {
            return loadSubjectKeyFromPvk(options);
        }
        catch (const crypto::CckyException&)
        {
            throw crypto::CckyException(
                "Can't access the key of the subject ('" + options.pvkFile + "')", false);
        }
    }

    return std::make_shared<OpenSslPrivateKey>(std::move(pkey));
}

void CertGenerator::generateCertificate(const MakeCertOptions& options, PrivateKeyPtr subjectKey)
{
    if (!options.endStr.empty() && options.months != 0)
    {
        throw std::invalid_argument("E and M options are mutually exclusive");
    }

    if (!options.keyContainer.empty())
    {
        throw crypto::CckyException(
            "Key containers (-sk) are not supported on this platform.", false);
    }

    if (!options.issuerKeyContainer.empty())
    {
        throw crypto::CckyException(
            "Issuer key containers (-ik) are not supported on this platform.", false);
    }

    if (options.hasStoreOptions)
    {
        throw crypto::CckyException(
            "Certificate stores (-ss, -sr, -is, -ir) are not supported on this platform.", false);
    }

    if (options.hasIssuerCert && options.issuerCertFile.empty())
    {
        throw crypto::CckyException(
            "Issuer certificate stores (-in, -is, -ir) are not supported on this platform.", false);
    }

    // Validate provider type
    int providerType = options.syProviderType;
    if (providerType != 0 && providerType != 1 && providerType != 3 && providerType != 12 &&
        providerType != 13)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw crypto::CckyException(msg, false);
    }

    // Validate keySpec
    if (options.keySpec != 1 && options.keySpec != 2)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw crypto::CckyException(msg, false);
    }

    // 1. Resolve Subject Key
    auto sslSubjectKey = std::dynamic_pointer_cast<OpenSslPrivateKey>(subjectKey);
    if (!sslSubjectKey)
    {
        throw crypto::CckyException("Invalid subject key type", false);
    }
    const auto& rawSubjectKey = sslSubjectKey->getInternal();

    // 2. Load Issuer
    auto issuerCert = loadIssuerCert(options);
    auto issuerKey = loadIssuerKey(options);

    // 3. Create Certificate
    auto cert = createUnsignedCertificate(options, rawSubjectKey, issuerCert);

    // 4. Add Extensions
    addBasicConstraints(cert.get(), options);
    addEku(cert.get(), options);
    addPolicyLink(cert.get(), options);
    addNetscape(cert.get(), options);

    // 5. Sign
    signCertificate(cert, rawSubjectKey, issuerKey, options);

    // 6. Write
    writeCertificate(cert, options);
}

} // namespace crypto
} // namespace ccky
