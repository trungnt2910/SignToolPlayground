#include "crypto/CertGenerator.h"

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include <windows.h>

#include <wincrypt.h>
#include <wintrust.h>

#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"
#include "crypto/PvkKey.h"
#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WinPrivateKey.h"
#include "crypto/windows/WinWrapper.h"
#include "crypto/windows/WindowsException.h"

namespace ccky
{
namespace crypto
{

namespace
{

// RAII helper for HCRYPTPROV with custom deletion logic for temp containers
struct ProviderCloser
{
    HCRYPTPROV h;
    std::wstring name;
    LPCWSTR provName;
    DWORD provType;
    bool shouldDelete;
    ~ProviderCloser()
    {
        if (h)
        {
            CryptReleaseContext(h, 0);
            if (shouldDelete)
            {
                HCRYPTPROV hDel = 0;
                CryptAcquireContextW(&hDel, name.c_str(), provName, provType, CRYPT_DELETEKEYSET);
            }
        }
    }
};

// RAII helper for HCRYPTPROV (issuer) with custom deletion logic for temp containers
struct IssuerProvCloser
{
    HCRYPTPROV h;
    std::wstring name;
    LPCWSTR provName;
    DWORD provType;
    bool shouldFree;
    bool shouldDelete;
    ~IssuerProvCloser()
    {
        if (h && shouldFree)
        {
            CryptReleaseContext(h, 0);
            if (shouldDelete)
            {
                HCRYPTPROV hDel = 0;
                CryptAcquireContextW(&hDel, name.c_str(), provName, provType, CRYPT_DELETEKEYSET);
            }
        }
    }
};

std::wstring getCngHashAlgId(const std::string& algo)
{
    std::string algoUpper = algo;
    std::transform(algoUpper.begin(), algoUpper.end(), algoUpper.begin(), ::toupper);
    return WinHelper::utf8ToWide(algoUpper);
}

LPCSTR getSignatureAlgorithmOid(const std::string& algo, const std::string& pubKeyOid)
{
    if (pubKeyOid.empty())
    {
        throw CckyException("Public key OID is empty", false);
    }

    // 1. Find the CNG public key algorithm name from the OID
    PCCRYPT_OID_INFO pPubKeyInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY,
        const_cast<LPSTR>(pubKeyOid.c_str()), CRYPT_PUBKEY_ALG_OID_GROUP_ID);
    if (!pPubKeyInfo || !pPubKeyInfo->pwszCNGAlgid)
    {
        throw CckyException("Unsupported public key algorithm OID: " + pubKeyOid, false);
    }

    // 2. Get the CNG hash algorithm name
    std::wstring wHashAlg = getCngHashAlgId(algo);

    // 3. Find the signature OID
    LPCWSTR rgwszCNGAlgs[2] = {wHashAlg.c_str(), pPubKeyInfo->pwszCNGAlgid};

    PCCRYPT_OID_INFO pSigInfo =
        CryptFindOIDInfo(CRYPT_OID_INFO_CNG_SIGN_KEY, rgwszCNGAlgs, CRYPT_SIGN_ALG_OID_GROUP_ID);

    if (!pSigInfo)
    {
        throw CckyException(
            "Unsupported signature algorithm: " + algo + " with public key OID " + pubKeyOid,
            false);
    }

    return pSigInfo->pszOID;
}

CertContextPtr loadSubjectCert(const MakeCertOptions& options)
{
    if (options.subjectCertFile.empty())
    {
        return nullptr;
    }
    std::wstring wSubjectCertFile = WinHelper::utf8ToWide(options.subjectCertFile);
    PCCERT_CONTEXT pTempCert = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wSubjectCertFile.c_str(),
            CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
            nullptr, nullptr, nullptr, reinterpret_cast<const void**>(&pTempCert)))
    {
        throw CckyException(
            "Can't access the certificate of the subject ('" + options.subjectCertFile + "')",
            false);
    }
    return CertContextPtr(pTempCert);
}

CertContextPtr loadIssuerCert(const MakeCertOptions& options)
{
    if (!options.hasIssuerCert)
    {
        return nullptr;
    }

    if (!options.issuerCertFile.empty())
    {
        std::wstring wIssuerCertFile = WinHelper::utf8ToWide(options.issuerCertFile);
        PCCERT_CONTEXT pTempCert = nullptr;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wIssuerCertFile.c_str(),
                CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0, nullptr, nullptr,
                nullptr, nullptr, nullptr, reinterpret_cast<const void**>(&pTempCert)))
        {
            throw CckyException(
                "Can't access the certificate of the issuer ('" + options.issuerCertFile + "')",
                false);
        }
        return CertContextPtr(pTempCert);
    }
    else if (!options.issuerName.empty())
    {
        std::wstring wIssuerStoreName = WinHelper::utf8ToWide(options.issuerStoreName);
        DWORD storeFlags = CERT_SYSTEM_STORE_CURRENT_USER;
        if (options.issuerStoreLocation == "localmachine")
        {
            storeFlags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
        }

        CertStorePtr hStore(
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL, storeFlags, wIssuerStoreName.c_str()));
        if (!hStore)
        {
            throw CckyException(
                "Failed to open issuer certificate store: " + options.issuerStoreName, false);
        }

        std::wstring wIssuerName = WinHelper::utf8ToWide(options.issuerName);
        PCCERT_CONTEXT pTempCert =
            CertFindCertificateInStore(hStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_STR_W, wIssuerName.c_str(), nullptr);
        if (!pTempCert)
        {
            throw CckyException(
                "Can't find the certificate of the issuer ('" + options.issuerName + "')", false);
        }
        return CertContextPtr(pTempCert);
    }
    return nullptr;
}

HCRYPTPROV loadIssuerKey(const MakeCertOptions& options, PCCERT_CONTEXT pIssuerCert,
    LPCWSTR providerName, DWORD providerType, DWORD& dwIssuerKeySpec, bool& freeIssuerProv,
    std::wstring& tempIssuerContainerName)
{
    HCRYPTPROV hIssuerProv = 0;
    freeIssuerProv = false;

    if (!options.issuerPvkFile.empty())
    {
        PvkKey issuerPvk;
        try
        {
            issuerPvk.load(options.issuerPvkFile);
        }
        catch (...)
        {
            throw CckyException(
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
            catch (const PvkIncorrectPasswordException&)
            {
                throw CckyException(
                    "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
            }
        }

        if (issuerPvk.getKeyType() != options.issuerKeySpec)
        {
            throw CckyException(
                "Can't access the key of the issuer ('" + options.issuerPvkFile + "')", false);
        }

        tempIssuerContainerName =
            L"Ccky_MakeCert_TempIssuerContainer_" + std::to_wstring(GetCurrentProcessId());
        if (!CryptAcquireContextW(&hIssuerProv, tempIssuerContainerName.c_str(), providerName,
                providerType, CRYPT_NEWKEYSET))
        {
            if (GetLastError() == NTE_EXISTS)
            {
                if (!CryptAcquireContextW(&hIssuerProv, tempIssuerContainerName.c_str(),
                        providerName, providerType, 0))
                {
                    throw CckyException("Failed to acquire crypt context for issuer.", false);
                }
            }
            else
            {
                throw CckyException("Failed to acquire crypt context for issuer.", false);
            }
        }
        freeIssuerProv = true;

        HCRYPTKEY hIssuerKey = 0;
        auto issuerPvkBlob = issuerPvk.getKeyData();
        if (!CryptImportKey(hIssuerProv, issuerPvkBlob.data(),
                static_cast<DWORD>(issuerPvkBlob.size()), 0, 0, &hIssuerKey))
        {
            CryptReleaseContext(hIssuerProv, 0);
            CryptAcquireContextW(&hIssuerProv, tempIssuerContainerName.c_str(), providerName,
                providerType, CRYPT_DELETEKEYSET);
            throw CckyException("Failed to import issuer private key.", false);
        }
        CryptDestroyKey(hIssuerKey);
    }
    else if (pIssuerCert)
    {
        BOOL fCallerFree = FALSE;
        if (!CryptAcquireCertificatePrivateKey(
                pIssuerCert, 0, nullptr, &hIssuerProv, &dwIssuerKeySpec, &fCallerFree))
        {
            throw CckyException("Can't access the key of the issuer.", false);
        }
        freeIssuerProv = fCallerFree;
    }
    return hIssuerProv;
}

HCRYPTPROV acquireSubjectContext(const MakeCertOptions& options, const std::wstring& containerName,
    LPCWSTR providerName, DWORD providerType)
{
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(
            &hProv, containerName.c_str(), providerName, providerType, CRYPT_NEWKEYSET))
    {
        if (GetLastError() == NTE_EXISTS)
        {
            if (!CryptAcquireContextW(&hProv, containerName.c_str(), providerName, providerType, 0))
            {
                throw CckyException("Can't create the key of the subject", false);
            }
        }
        else
        {
            throw CckyException("Can't create the key of the subject", false);
        }
    }
    return hProv;
}

PrivateKeyPtr loadSubjectKeyFromPvk(const MakeCertOptions& options,
    const std::wstring& containerName, LPCWSTR providerName, DWORD providerType)
{
    CryptProvPtr hProv(acquireSubjectContext(options, containerName, providerName, providerType));

    bool isTempContainer = options.keyContainer.empty();
    auto keysetDeleter = std::make_unique<KeySetDeleter>(
        containerName, providerName ? providerName : L"", providerType);
    if (!isTempContainer)
    {
        keysetDeleter->dismiss();
    }

    PvkKey pvk;
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
        catch (const PvkIncorrectPasswordException&)
        {
            throw CckyException(
                "Can't access the key of the subject ('" + options.pvkFile + "')", false);
        }
    }
    if (pvk.getKeyType() != options.keySpec)
    {
        throw CckyException(
            "Can't access the key of the subject ('" + options.pvkFile + "')", false);
    }
    auto pvkBlob = pvk.getKeyData();

    HCRYPTKEY rawKey = 0;
    if (!CryptImportKey(hProv.get(), pvkBlob.data(), static_cast<DWORD>(pvkBlob.size()), 0,
            CRYPT_EXPORTABLE, &rawKey))
    {
        throw CckyException(
            "Can't access the key of the subject ('" + options.pvkFile + "')", false);
    }
    CryptKeyPtr hKey(rawKey);

    return std::make_shared<WinPrivateKey>(std::move(hProv), std::move(hKey), containerName,
        providerName ? providerName : L"", providerType, options.keySpec, std::move(keysetDeleter));
}

void saveSubjectKeyToPvk(
    HCRYPTKEY hKey, HCRYPTPROV hProv, const MakeCertOptions& options, const std::string& password)
{
    DWORD cbPvkBlob = 0;
    if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, nullptr, &cbPvkBlob))
    {
        throw CckyException("Failed to get exported private key size.");
    }

    std::vector<uint8_t> pvkBlob(cbPvkBlob);
    if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, pvkBlob.data(), &cbPvkBlob))
    {
        throw CckyException("Failed to export private key.");
    }

    PvkKey pvkFileKey;
    pvkFileKey.setKeyData(pvkBlob, options.keySpec);
    if (!password.empty())
    {
        pvkFileKey.encrypt(password);
    }
    pvkFileKey.save(options.pvkFile);
}

CERT_NAME_BLOB encodeSubjectName(const std::wstring& wSubjectName, std::vector<BYTE>& nameData)
{
    CERT_NAME_BLOB nameBlob;
    nameBlob.cbData = 0;
    nameBlob.pbData = nullptr;

    if (!CertStrToNameW(X509_ASN_ENCODING, wSubjectName.c_str(), CERT_X500_NAME_STR, nullptr,
            nullptr, &nameBlob.cbData, nullptr))
    {
        throw CckyException("Failed to convert subject name.");
    }

    nameData.resize(nameBlob.cbData);
    nameBlob.pbData = nameData.data();
    if (!CertStrToNameW(X509_ASN_ENCODING, wSubjectName.c_str(), CERT_X500_NAME_STR, nullptr,
            nameBlob.pbData, &nameBlob.cbData, nullptr))
    {
        throw CckyException("Failed to encode subject name.");
    }
    return nameBlob;
}

std::vector<BYTE> encodeBasicConstraints(const MakeCertOptions& options)
{
    std::vector<BYTE> bcEncoded;
    if (options.cyCertType == "authority" || options.cyCertType == "end")
    {
        CERT_BASIC_CONSTRAINTS2_INFO bcInfo;
        ZeroMemory(&bcInfo, sizeof(bcInfo));
        if (options.cyCertType == "authority")
        {
            bcInfo.fCA = TRUE;
            if (options.hasPathLen)
            {
                bcInfo.fPathLenConstraint = TRUE;
                bcInfo.dwPathLenConstraint = options.pathLen;
            }
        }
        else
        {
            bcInfo.fCA = FALSE;
            bcInfo.fPathLenConstraint = TRUE;
            bcInfo.dwPathLenConstraint = 0;
        }

        DWORD cbEncoded = 0;
        if (!CryptEncodeObject(
                X509_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, &bcInfo, nullptr, &cbEncoded))
        {
            throw CckyException("Failed to determine Basic Constraints encoding length.");
        }
        bcEncoded.resize(cbEncoded);
        if (!CryptEncodeObject(
                X509_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, &bcInfo, bcEncoded.data(), &cbEncoded))
        {
            throw CckyException("Failed to encode Basic Constraints.");
        }
    }
    return bcEncoded;
}

std::vector<BYTE> encodeEku(const MakeCertOptions& options)
{
    std::vector<BYTE> ekuEncoded;
    std::vector<std::string> allEkuOids = options.ekuOids;
    if (options.authority == "commercial")
    {
        allEkuOids.push_back(SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID);
    }
    else if (options.authority == "individual")
    {
        allEkuOids.push_back(SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
    }

    std::vector<LPSTR> ekuOidPtrs;
    if (!allEkuOids.empty())
    {
        CERT_ENHKEY_USAGE ekuInfo;
        ekuInfo.cUsageIdentifier = static_cast<DWORD>(allEkuOids.size());
        for (const auto& oid : allEkuOids)
        {
            ekuOidPtrs.push_back(const_cast<LPSTR>(oid.c_str()));
        }
        ekuInfo.rgpszUsageIdentifier = ekuOidPtrs.data();

        DWORD cbEncoded = 0;
        if (!CryptEncodeObject(
                X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE, &ekuInfo, nullptr, &cbEncoded))
        {
            // Windows backend silently fails for invalid EKUs.
            throw std::invalid_argument("Failed to encode EKU (invalid OID?)");
        }
        ekuEncoded.resize(cbEncoded);
        if (!CryptEncodeObject(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE, &ekuInfo,
                ekuEncoded.data(), &cbEncoded))
        {
            throw std::invalid_argument("Failed to encode EKU");
        }
    }
    return ekuEncoded;
}

std::vector<BYTE> encodePolicyLink(const MakeCertOptions& options)
{
    std::vector<BYTE> policyEncoded;
    if (options.policyLink.empty())
    {
        return policyEncoded;
    }

    std::wstring wUrl = WinHelper::utf8ToWide(options.policyLink);

    SPC_LINK link;
    link.dwLinkChoice = SPC_URL_LINK_CHOICE;
    link.pwszUrl = const_cast<LPWSTR>(wUrl.c_str());

    SPC_SP_AGENCY_INFO info;
    ZeroMemory(&info, sizeof(info));
    info.pPolicyInformation = &link;

    DWORD cbEncoded = 0;
    if (CryptEncodeObject(X509_ASN_ENCODING, SPC_SP_AGENCY_INFO_STRUCT, &info, nullptr, &cbEncoded))
    {
        policyEncoded.resize(cbEncoded);
        if (!CryptEncodeObject(X509_ASN_ENCODING, SPC_SP_AGENCY_INFO_STRUCT, &info,
                policyEncoded.data(), &cbEncoded))
        {
            policyEncoded.clear();
        }
    }
    return policyEncoded;
}

std::vector<BYTE> encodeNetscape(const MakeCertOptions& options)
{
    std::vector<BYTE> nscpEncoded;
    if (options.netscape)
    {
        BYTE bits = 0x80; // SSL Client
        CRYPT_BIT_BLOB bitBlob;
        bitBlob.cbData = 1;
        bitBlob.pbData = &bits;
        bitBlob.cUnusedBits = 0;
        DWORD cbEncoded = 0;
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_BITS, &bitBlob, nullptr, &cbEncoded))
        {
            nscpEncoded.resize(cbEncoded);
            if (!CryptEncodeObject(
                    X509_ASN_ENCODING, X509_BITS, &bitBlob, nscpEncoded.data(), &cbEncoded))
            {
                nscpEncoded.clear();
            }
        }
    }
    return nscpEncoded;
}

PCCERT_CONTEXT signCertificate(const CERT_PUBLIC_KEY_INFO* pSubjectPublicKeyInfo,
    const CERT_NAME_BLOB* pSubjectName, PCCERT_CONTEXT pIssuerCert, HCRYPTPROV hIssuerProv,
    DWORD dwIssuerKeySpec, PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
    const SYSTEMTIME* pStartTime, const SYSTEMTIME* pEndTime, const CERT_EXTENSIONS* pExtensions,
    long serialNum, bool hasSerialNum)
{
    CERT_INFO certInfo = {0};
    certInfo.dwVersion = CERT_V3;

    std::vector<uint8_t> serialBuf;
    if (hasSerialNum)
    {
        serialBuf.resize(sizeof(serialNum));
        for (size_t i = 0; i < sizeof(serialNum); ++i)
        {
            serialBuf[i] = static_cast<uint8_t>((serialNum >> (8 * i)) & 0xFF);
        }
    }
    else
    {
        long randSerial = 0;
        do
        {
            CryptoFactory::getRandomBytes(&randSerial, sizeof(randSerial));
            randSerial &= 0x7FFFFFFF; // Ensure it is positive and fits in 31 bits
        } while (randSerial == 0);

        serialBuf.resize(sizeof(randSerial));
        for (size_t i = 0; i < sizeof(randSerial); ++i)
        {
            serialBuf[i] = static_cast<uint8_t>((randSerial >> (8 * i)) & 0xFF);
        }
    }
    // This must be little-endian.
    certInfo.SerialNumber.pbData = serialBuf.data();
    certInfo.SerialNumber.cbData = static_cast<DWORD>(serialBuf.size());

    certInfo.SignatureAlgorithm = *pSignatureAlgorithm;

    if (pIssuerCert)
    {
        certInfo.Issuer = pIssuerCert->pCertInfo->Subject;
    }
    else
    {
        certInfo.Issuer = *pSubjectName; // Self-signed
    }

    if (!SystemTimeToFileTime(pStartTime, &certInfo.NotBefore))
    {
        throw CckyException("Failed to convert start time.");
    }
    if (!SystemTimeToFileTime(pEndTime, &certInfo.NotAfter))
    {
        throw CckyException("Failed to convert end time.");
    }

    certInfo.Subject = *pSubjectName;
    certInfo.SubjectPublicKeyInfo = *pSubjectPublicKeyInfo;

    if (pExtensions && pExtensions->cExtension > 0)
    {
        certInfo.cExtension = pExtensions->cExtension;
        certInfo.rgExtension = pExtensions->rgExtension;
    }

    DWORD cbEncoded = 0;
    if (!CryptSignAndEncodeCertificate(hIssuerProv, dwIssuerKeySpec, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &certInfo, pSignatureAlgorithm, nullptr, nullptr, &cbEncoded))
    {
        throw CckyException("Failed to get signed certificate size.");
    }

    std::vector<uint8_t> encodedBuf(cbEncoded);
    if (!CryptSignAndEncodeCertificate(hIssuerProv, dwIssuerKeySpec, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &certInfo, pSignatureAlgorithm, nullptr, encodedBuf.data(),
            &cbEncoded))
    {
        throw CckyException("Failed to sign and encode certificate.");
    }

    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, encodedBuf.data(), cbEncoded);
    if (!pCertContext)
    {
        throw CckyException("Failed to create certificate context from encoded bytes.");
    }

    return pCertContext;
}

void writeCertificate(
    PCCERT_CONTEXT pCertContext, const MakeCertOptions& options, WinPrivateKey* subjectKey)
{
    if (!options.outputCertFile.empty())
    {
        std::wstring wOutputCertFile = WinHelper::utf8ToWide(options.outputCertFile);
        HandlePtr hFile(CreateFileW(wOutputCertFile.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (hFile.get() == INVALID_HANDLE_VALUE)
        {
            throw CckyException(
                "Failed to open output certificate file: " + options.outputCertFile, false);
        }

        DWORD dwWritten = 0;
        if (!WriteFile(hFile.get(), pCertContext->pbCertEncoded, pCertContext->cbCertEncoded,
                &dwWritten, nullptr))
        {
            throw CckyException("Failed to write certificate to file.", false);
        }
    }

    if (!options.ssStoreName.empty())
    {
        std::wstring wStoreName = WinHelper::utf8ToWide(options.ssStoreName);
        DWORD storeFlags = CERT_SYSTEM_STORE_CURRENT_USER;
        if (options.srStoreLocation == "localmachine")
        {
            storeFlags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
        }

        CertStorePtr hStore(
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL, storeFlags, wStoreName.c_str()));
        if (!hStore)
        {
            throw CckyException(
                "Failed to open subject certificate store: " + options.ssStoreName, false);
        }

        // Link private key to certificate
        if (subjectKey && subjectKey->getInternalProv())
        {
            CRYPT_KEY_PROV_INFO keyProvInfo;
            ZeroMemory(&keyProvInfo, sizeof(keyProvInfo));
            std::wstring containerName = WinHelper::utf8ToWide(subjectKey->getContainerName());
            std::wstring providerName = WinHelper::utf8ToWide(subjectKey->getProviderName());

            keyProvInfo.pwszContainerName = const_cast<LPWSTR>(containerName.c_str());
            keyProvInfo.pwszProvName =
                providerName.empty() ? nullptr : const_cast<LPWSTR>(providerName.c_str());
            keyProvInfo.dwProvType = subjectKey->getProviderType();
            keyProvInfo.dwFlags = 0;
            keyProvInfo.cProvParam = 0;
            keyProvInfo.rgProvParam = nullptr;
            keyProvInfo.dwKeySpec = subjectKey->getKeySpec();

            if (!CertSetCertificateContextProperty(
                    pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo))
            {
                throw CckyException("Failed to set key provider property on certificate.", false);
            }
        }

        if (!CertAddCertificateContextToStore(
                hStore.get(), pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
        {
            throw CckyException(
                "Failed to add certificate to store: " + options.ssStoreName, false);
        }
    }
}
} // namespace

PrivateKeyPtr CertGenerator::loadSubjectKey(const MakeCertOptions& options)
{
    if (!options.subjectCertFile.empty())
    {
        auto pCert = loadSubjectCert(options);
        return std::make_shared<WinPrivateKey>(std::move(pCert));
    }
    if (!options.pvkFile.empty())
    {
        std::wstring containerName =
            L"Ccky_MakeCert_TempContainer_" + std::to_wstring(GetCurrentProcessId());
        LPCWSTR providerName = nullptr;
        std::wstring wProviderName;
        if (!options.spProviderName.empty())
        {
            wProviderName = WinHelper::utf8ToWide(options.spProviderName);
            providerName = wProviderName.c_str();
        }
        DWORD providerType = options.syProviderType == 0 ? PROV_RSA_FULL : options.syProviderType;
        try
        {
            return loadSubjectKeyFromPvk(options, containerName, providerName, providerType);
        }
        catch (const crypto::CckyException&)
        {
            throw;
        }
    }
    return nullptr;
}

PrivateKeyPtr CertGenerator::generateSubjectKey(const MakeCertOptions& options)
{
    if (!options.pvkFile.empty() && std::filesystem::exists(options.pvkFile))
    {
        throw CckyException(
            "Can't create the key of the subject ('" + options.pvkFile + "')", false);
    }

    // Validate provider type
    int valProviderType = options.syProviderType;
    if (valProviderType != 0 && valProviderType != 1 && valProviderType != 3 &&
        valProviderType != 12 && valProviderType != 13)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw CckyException(msg, false);
    }

    // Validate keySpec
    if (options.keySpec != 1 && options.keySpec != 2)
    {
        std::string msg = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            msg += " ('" + options.pvkFile + "')";
        }
        throw CckyException(msg, false);
    }

    std::wstring containerName;
    bool isTempContainer = true;
    if (!options.keyContainer.empty())
    {
        containerName = WinHelper::utf8ToWide(options.keyContainer);
        isTempContainer = false;
    }
    else if (options.pvkFile.empty())
    {
        if (!options.ssStoreName.empty())
        {
            containerName = L"Ccky_MakeCert_Key_" + std::to_wstring(GetCurrentProcessId());
            isTempContainer = false;
        }
        else
        {
            containerName =
                L"Ccky_MakeCert_TempContainer_" + std::to_wstring(GetCurrentProcessId());
        }
    }
    else
    {
        containerName = L"Ccky_MakeCert_TempContainer_" + std::to_wstring(GetCurrentProcessId());
    }

    LPCWSTR providerName = nullptr;
    std::wstring wProviderName;
    if (!options.spProviderName.empty())
    {
        wProviderName = WinHelper::utf8ToWide(options.spProviderName);
        providerName = wProviderName.c_str();
    }
    DWORD providerType = options.syProviderType == 0 ? PROV_RSA_FULL : options.syProviderType;

    CryptProvPtr hProv(acquireSubjectContext(options, containerName, providerName, providerType));

    auto keysetDeleter = std::make_unique<KeySetDeleter>(
        containerName, providerName ? providerName : L"", providerType);
    if (!isTempContainer)
    {
        keysetDeleter->dismiss();
    }

    DWORD dwFlags = (options.exportable || !options.pvkFile.empty()) ? CRYPT_EXPORTABLE : 0;
    DWORD dwKeyLen = options.keyLen;
    if (dwKeyLen == 0)
    {
        dwKeyLen = (providerType == PROV_DSS || providerType == PROV_DSS_DH) ? 512 : 2048;
    }
    dwFlags |= (dwKeyLen << 16);

    HCRYPTKEY rawKey = 0;
    if (!CryptGenKey(hProv.get(), options.keySpec, dwFlags, &rawKey))
    {
        std::string error = "Can't create the key of the subject";
        if (!options.pvkFile.empty())
        {
            error += "'" + options.pvkFile + "'";
        }
        throw CckyException(error, false);
    }
    CryptKeyPtr hKey(rawKey);

    std::string password;
    if (!options.pvkFile.empty())
    {
        if (options.createPasswordCallback)
        {
            password = options.createPasswordCallback();
        }
        saveSubjectKeyToPvk(hKey.get(), hProv.get(), options, password);

        // Destroy the key and release context to force reload
        hKey.reset();
        hProv.reset();

        // Delete the keyset
        HCRYPTPROV hDel = 0;
        CryptAcquireContextW(
            &hDel, containerName.c_str(), providerName, providerType, CRYPT_DELETEKEYSET);

        keysetDeleter->dismiss();

        return loadSubjectKeyFromPvk(options, containerName, providerName, providerType);
    }

    return std::make_shared<WinPrivateKey>(std::move(hProv), std::move(hKey), containerName,
        providerName ? providerName : L"", providerType, options.keySpec, std::move(keysetDeleter));
}

void CertGenerator::generateCertificate(const MakeCertOptions& options, PrivateKeyPtr subjectKey)
{
    if (!options.endStr.empty() && options.months != 0)
    {
        throw std::invalid_argument("E and M options are mutually exclusive");
    }

    // 1. Convert Subject Name
    std::wstring wSubjectName = WinHelper::utf8ToWide(options.subjectName);

    auto winSubjectKey = std::dynamic_pointer_cast<WinPrivateKey>(subjectKey);
    if (!winSubjectKey)
    {
        throw CckyException("Invalid subject key type", false);
    }

    HCRYPTPROV hProv = winSubjectKey->getInternalProv();

    // 4. Load Issuer
    CertContextPtr pIssuerCert = loadIssuerCert(options);
    HCRYPTPROV hIssuerProv = 0;
    DWORD dwIssuerKeySpec = options.issuerKeySpec;
    bool freeIssuerProv = false;
    std::wstring tempIssuerContainerName;

    LPCWSTR providerName = nullptr;
    std::wstring wProviderName;
    if (!options.spProviderName.empty())
    {
        wProviderName = WinHelper::utf8ToWide(options.spProviderName);
        providerName = wProviderName.c_str();
    }
    DWORD providerType = options.syProviderType == 0 ? PROV_RSA_FULL : options.syProviderType;

    if (options.hasIssuerCert)
    {
        hIssuerProv = loadIssuerKey(options, pIssuerCert.get(), providerName, providerType,
            dwIssuerKeySpec, freeIssuerProv, tempIssuerContainerName);
    }
    else
    {
        hIssuerProv = hProv;
        dwIssuerKeySpec = options.keySpec;
        if (hIssuerProv == 0)
        {
            tempIssuerContainerName =
                L"Ccky_MakeCert_TempIssuer_" + std::to_wstring(GetCurrentProcessId());
            hIssuerProv =
                acquireSubjectContext(options, tempIssuerContainerName, providerName, providerType);
            freeIssuerProv = true;
            HCRYPTKEY hTempKeyRaw = 0;
            if (!CryptGenKey(hIssuerProv, options.keySpec, 0, &hTempKeyRaw))
            {
                throw WindowsException("Failed to generate temporary signing key");
            }
            CryptKeyPtr hTempKey(hTempKeyRaw);
        }
    }
    IssuerProvCloser issuerProvCloser{hIssuerProv, tempIssuerContainerName, providerName,
        providerType, freeIssuerProv, !tempIssuerContainerName.empty()};

    // 7. Get Public Key Info
    const CERT_PUBLIC_KEY_INFO* pSubjectPublicKeyInfo = winSubjectKey->getPublicKeyInfo();
    if (!pSubjectPublicKeyInfo)
    {
        throw CckyException("Failed to get subject public key info.");
    }

    // 8. Encode Subject Name
    std::vector<BYTE> nameData;
    CERT_NAME_BLOB nameBlob = encodeSubjectName(wSubjectName, nameData);

    // 9. Setup Algorithm ID
    CRYPT_ALGORITHM_IDENTIFIER sigAlg;
    ZeroMemory(&sigAlg, sizeof(sigAlg));

    std::string pubKeyOid = pIssuerCert
                                ? pIssuerCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId
                                : pSubjectPublicKeyInfo->Algorithm.pszObjId;

    sigAlg.pszObjId = const_cast<LPSTR>(getSignatureAlgorithmOid(options.algo, pubKeyOid));

    // 10. Dates
    SYSTEMTIME stStartTime;
    GetSystemTime(&stStartTime); // Default to now
    if (!options.startStr.empty())
    {
        int m, d, y;
        if (std::sscanf(options.startStr.c_str(), "%d/%d/%d", &m, &d, &y) == 3)
        {
            ZeroMemory(&stStartTime, sizeof(stStartTime));
            stStartTime.wYear = y;
            stStartTime.wMonth = m;
            stStartTime.wDay = d;
        }
    }

    SYSTEMTIME stEndTime;
    ZeroMemory(&stEndTime, sizeof(stEndTime));
    if (!options.endStr.empty())
    {
        int m, d, y;
        if (std::sscanf(options.endStr.c_str(), "%d/%d/%d", &m, &d, &y) == 3)
        {
            stEndTime.wYear = y;
            stEndTime.wMonth = m;
            stEndTime.wDay = d;
        }
    }
    else if (options.months > 0)
    {
        stEndTime = stStartTime;
        int monthsToAdd = options.months;
        stEndTime.wMonth += monthsToAdd;
        while (stEndTime.wMonth > 12)
        {
            stEndTime.wMonth -= 12;
            stEndTime.wYear += 1;
        }
    }
    else
    {
        stEndTime.wYear = 2039;
        stEndTime.wMonth = 12;
        stEndTime.wDay = 31;
        stEndTime.wHour = 23;
        stEndTime.wMinute = 59;
        stEndTime.wSecond = 59;
    }

    // 11. Extensions
    std::vector<CERT_EXTENSION> extensions;
    std::vector<BYTE> bcEncoded = encodeBasicConstraints(options);
    if (!bcEncoded.empty())
    {
        CERT_EXTENSION ext;
        ext.pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
        ext.fCritical = TRUE;
        ext.Value.cbData = static_cast<DWORD>(bcEncoded.size());
        ext.Value.pbData = bcEncoded.data();
        extensions.push_back(ext);
    }

    std::vector<BYTE> ekuEncoded = encodeEku(options);
    if (!ekuEncoded.empty())
    {
        CERT_EXTENSION ext;
        ext.pszObjId = const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(ekuEncoded.size());
        ext.Value.pbData = ekuEncoded.data();
        extensions.push_back(ext);
    }

    std::vector<BYTE> policyEncoded = encodePolicyLink(options);
    if (!policyEncoded.empty())
    {
        CERT_EXTENSION ext;
        ext.pszObjId = const_cast<LPSTR>(SPC_SP_AGENCY_INFO_OBJID);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(policyEncoded.size());
        ext.Value.pbData = policyEncoded.data();
        extensions.push_back(ext);
    }

    std::vector<BYTE> nscpEncoded = encodeNetscape(options);
    if (!nscpEncoded.empty())
    {
        CERT_EXTENSION ext;
        ext.pszObjId = const_cast<LPSTR>(szOID_NETSCAPE_CERT_TYPE);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(nscpEncoded.size());
        ext.Value.pbData = nscpEncoded.data();
        extensions.push_back(ext);
    }

    CERT_EXTENSIONS certExts;
    certExts.cExtension = static_cast<DWORD>(extensions.size());
    certExts.rgExtension = extensions.data();

    // 12. Sign Certificate
    CertContextPtr pCertContext(signCertificate(pSubjectPublicKeyInfo, &nameBlob, pIssuerCert.get(),
        hIssuerProv, dwIssuerKeySpec, &sigAlg, &stStartTime, &stEndTime, &certExts,
        options.serialNum, options.hasSerialNum));

    // 13. Write Certificate
    writeCertificate(pCertContext.get(), options, winSubjectKey.get());
}

} // namespace crypto
} // namespace ccky
