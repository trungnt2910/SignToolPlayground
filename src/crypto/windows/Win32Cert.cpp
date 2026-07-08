#include "crypto/windows/Win32Cert.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#include <windows.h>

#include <wincrypt.h>
#include <wintrust.h>

#include "crypto/CckyProbeAllocate.h"
#include "crypto/Time.h"
#include "crypto/windows/Win32PrivateKey.h"
#include "crypto/windows/Win32Time.h"
#include "crypto/windows/WinHelper.h"

namespace ccky
{
namespace crypto
{

Win32Cert::Win32Cert(CertContextPtr cert) : m_cert(std::move(cert)) {}

// Encoding, Hashes & Algorithms
std::vector<uint8_t> Win32Cert::getEncoded() const
{
    if (m_cert == nullptr || !m_cert->pbCertEncoded || m_cert->cbCertEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(
        m_cert->pbCertEncoded, m_cert->pbCertEncoded + m_cert->cbCertEncoded);
}

std::string Win32Cert::getSerialNumber() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    CRYPT_INTEGER_BLOB* serial = &m_cert->pCertInfo->SerialNumber;
    std::stringstream ss;
    for (int i = static_cast<int>(serial->cbData) - 1; i >= 0; --i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(serial->pbData[i]);
        if (i > 0)
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string Win32Cert::getSha1() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (CertGetCertificateContextProperty(m_cert.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
    {
        std::stringstream ss;
        for (DWORD i = 0; i < len; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
    return "";
}

std::string Win32Cert::getSha1Thumbprint() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (!CertGetCertificateContextProperty(m_cert.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
        if ((i % 4 == 3) && (i + 1 < len))
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string Win32Cert::getMd5Thumbprint() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    BYTE hash[16];
    DWORD len = sizeof(hash);
    if (!CertGetCertificateContextProperty(m_cert.get(), CERT_MD5_HASH_PROP_ID, hash, &len))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
        if ((i % 4 == 3) && (i + 1 < len))
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string Win32Cert::getSignatureAlgorithm() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return m_cert->pCertInfo->SignatureAlgorithm.pszObjId;
}

// Subject Information
std::string Win32Cert::getCommonName() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    std::wstring wbuf;
    CckyProbeAllocate<CertGetNameStringW, CckyProbeReturnPositive{}>(m_cert.get(),
        CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, CckyProbeBuffer(wbuf), CckyProbeSize{});
    return WinHelper::wideToUtf8(wbuf.c_str());
}

std::string Win32Cert::getSubjectDisplay() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDisplay(&m_cert->pCertInfo->Subject);
}

std::string Win32Cert::getSubjectDN() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDN(&m_cert->pCertInfo->Subject);
}

// Issuer Information
std::string Win32Cert::getIssuerName() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    std::wstring wbuf;
    CckyProbeAllocate<CertGetNameStringW, CckyProbeReturnPositive{}>(m_cert.get(),
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, CckyProbeBuffer(wbuf),
        CckyProbeSize{});
    return WinHelper::wideToUtf8(wbuf.c_str());
}

std::string Win32Cert::getIssuerDisplay() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDisplay(&m_cert->pCertInfo->Issuer);
}

std::string Win32Cert::getIssuerDN() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDN(&m_cert->pCertInfo->Issuer);
}

// Validity Period
std::string Win32Cert::getNotBefore() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return Time::format(Win32Time::toChrono(m_cert->pCertInfo->NotBefore));
}

std::string Win32Cert::getNotAfter() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    return Time::format(Win32Time::toChrono(m_cert->pCertInfo->NotAfter));
}

// Key Information
int Win32Cert::getKeyLength() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return 0;
    }
    return CertGetPublicKeyLength(X509_ASN_ENCODING, &m_cert->pCertInfo->SubjectPublicKeyInfo);
}

std::string Win32Cert::getKeyMd5Thumbprint() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }

    std::vector<BYTE> encodedBuf;
    if (!CckyProbeAllocate<CryptEncodeObject, CckyProbeReturnPositive{}>(X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, &m_cert->pCertInfo->SubjectPublicKeyInfo,
            CckyProbeBuffer(encodedBuf), CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }

    CryptProvPtr hProv;
    if (!CryptAcquireContextW(&hProv.init(), nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return "";
    }
    CryptHashPtr hHash;
    if (!CryptCreateHash(hProv.get(), CALG_MD5, 0, 0, &hHash.init()))
    {
        return "";
    }
    if (!CryptHashData(hHash.get(), encodedBuf.data(), encodedBuf.size(), 0))
    {
        return "";
    }
    BYTE hash[16];
    DWORD len = sizeof(hash);
    if (!CryptGetHashParam(hHash.get(), HP_HASHVAL, hash, &len, 0))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
        if ((i % 4 == 3) && (i + 1 < len))
        {
            ss << " ";
        }
    }
    return ss.str();
}

std::string Win32Cert::getKeySha256Thumbprint() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    std::vector<BYTE> encodedBuf;
    if (!CckyProbeAllocate<CryptEncodeObject, CckyProbeReturnPositive{}>(X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, &m_cert->pCertInfo->SubjectPublicKeyInfo,
            CckyProbeBuffer(encodedBuf), CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }

    CryptProvPtr hProv;
    if (!CryptAcquireContextW(&hProv.init(), nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return "";
    }
    CryptHashPtr hHash;
    if (!CryptCreateHash(hProv.get(), CALG_SHA_256, 0, 0, &hHash.init()))
    {
        return "";
    }
    if (!CryptHashData(hHash.get(), encodedBuf.data(), encodedBuf.size(), 0))
    {
        return "";
    }
    BYTE hash[32];
    DWORD len = sizeof(hash);
    if (!CryptGetHashParam(hHash.get(), HP_HASHVAL, hash, &len, 0))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Private Key Information
bool Win32Cert::hasPrivateKey() const
{
    if (m_cert == nullptr)
    {
        return false;
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) &&
        size > 0)
    {
        return true;
    }
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    if (CryptAcquireCertificatePrivateKey(m_cert.get(),
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG |
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
            nullptr, &hKeyOrProv, &dwKeySpec, &fCallerFree))
    {
        if (fCallerFree)
        {
            if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
            {
                NCryptFreeObject(hKeyOrProv);
            }
            else
            {
                CryptReleaseContext(hKeyOrProv, 0);
            }
        }
        return true;
    }
    return false;
}

PrivateKeyPtr Win32Cert::getPrivateKey() const
{
    if (!hasPrivateKey())
    {
        return nullptr;
    }
    return std::make_shared<Win32PrivateKey>(m_cert);
}

bool Win32Cert::isPrivateKeyExportable() const
{
    if (m_cert == nullptr)
    {
        return false;
    }
    std::vector<uint8_t> buf;
    if (!CckyProbeAllocate<CertGetCertificateContextProperty, CckyProbeReturnPositive{}>(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, CckyProbeBuffer(buf),
            CckyProbeBytesRef<DWORD>()))
    {
        return false;
    }
    auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
    CryptProvPtr hProv;
    if (!CryptAcquireContextW(
            &hProv.init(), info->pwszContainerName, info->pwszProvName, info->dwProvType, 0))
    {
        return false;
    }
    CryptKeyPtr hKey;
    DWORD keySpec = info->dwKeySpec;
    if (!CryptGetUserKey(hProv.get(), keySpec, &hKey.init()) &&
        !CryptGetUserKey(hProv.get(), AT_KEYEXCHANGE, &hKey.init()) &&
        !CryptGetUserKey(hProv.get(), AT_SIGNATURE, &hKey.init()))
    {
        return false;
    }
    DWORD exportSize = 0;
    if (CryptExportKey(hKey.get(), 0, PRIVATEKEYBLOB, 0, nullptr, &exportSize))
    {
        return true;
    }
    return false;
}

// Provider Information
std::string Win32Cert::getProviderType() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    std::vector<uint8_t> buf;
    if (!CckyProbeAllocate<CertGetCertificateContextProperty, CckyProbeReturnPositive{}>(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, CckyProbeBuffer(buf),
            CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }
    auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
    return std::to_string(info->dwProvType);
}

std::string Win32Cert::getProviderName() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    std::vector<uint8_t> buf;
    if (!CckyProbeAllocate<CertGetCertificateContextProperty, CckyProbeReturnPositive{}>(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, CckyProbeBuffer(buf),
            CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }
    auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
    if (!info->pwszProvName)
    {
        return "";
    }
    return WinHelper::wideToUtf8(info->pwszProvName);
}

std::string Win32Cert::getContainerName() const
{
    if (m_cert == nullptr)
    {
        return "";
    }
    std::vector<uint8_t> buf;
    if (!CckyProbeAllocate<CertGetCertificateContextProperty, CckyProbeReturnPositive{}>(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, CckyProbeBuffer(buf),
            CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }
    auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
    if (!info->pwszContainerName)
    {
        return "";
    }
    return WinHelper::wideToUtf8(info->pwszContainerName);
}

// Extensions & Policy Attributes
bool Win32Cert::isCA() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return false;
    }
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!ext)
    {
        return false;
    }
    CERT_BASIC_CONSTRAINTS2_INFO bcInfo;
    DWORD cbInfo = sizeof(bcInfo);
    if (!CryptDecodeObject(X509_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, ext->Value.pbData,
            ext->Value.cbData, 0, &bcInfo, &cbInfo))
    {
        return false;
    }
    return bcInfo.fCA == TRUE;
}

int Win32Cert::getPathLenConstraint() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return -1;
    }
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!ext)
    {
        return -1;
    }
    CERT_BASIC_CONSTRAINTS2_INFO bcInfo;
    DWORD cbInfo = sizeof(bcInfo);
    if (!CryptDecodeObject(X509_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, ext->Value.pbData,
            ext->Value.cbData, 0, &bcInfo, &cbInfo))
    {
        return -1;
    }
    if (!bcInfo.fPathLenConstraint)
    {
        return -1;
    }
    return static_cast<int>(bcInfo.dwPathLenConstraint);
}

std::vector<std::string> Win32Cert::getEnhancedKeyUsage() const
{
    std::vector<std::string> res;
    if (m_cert == nullptr)
    {
        return res;
    }
    std::vector<BYTE> usageBuf;
    if (!CckyProbeAllocate<CertGetEnhancedKeyUsage, CckyProbeReturnPositive{}>(
            m_cert.get(), 0, CckyProbeBuffer(usageBuf), CckyProbeBytesRef<DWORD>()))
    {
        return res;
    }
    PCERT_ENHKEY_USAGE pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(usageBuf.data());
    for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i)
    {
        res.push_back(pUsage->rgpszUsageIdentifier[i]);
    }
    return res;
}

uint32_t Win32Cert::getNetscapeCertType() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return 0;
    }
    PCERT_EXTENSION pExt = CertFindExtension(
        szOID_NETSCAPE_CERT_TYPE, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!pExt)
    {
        return 0;
    }
    std::vector<BYTE> bitsBuf;
    if (!CckyProbeAllocate<CryptDecodeObject, CckyProbeReturnPositive{}>(X509_ASN_ENCODING,
            X509_BITS, pExt->Value.pbData, pExt->Value.cbData, 0, CckyProbeBuffer(bitsBuf),
            CckyProbeBytesRef<DWORD>()))
    {
        return 0;
    }
    PCRYPT_BIT_BLOB pBits = reinterpret_cast<PCRYPT_BIT_BLOB>(bitsBuf.data());
    if (pBits->cbData > 0)
    {
        return pBits->pbData[0];
    }
    return 0;
}

std::string Win32Cert::getPolicyLink() const
{
    if (m_cert == nullptr || !m_cert->pCertInfo)
    {
        return "";
    }
    PCERT_EXTENSION pExt = CertFindExtension(
        SPC_SP_AGENCY_INFO_OBJID, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!pExt)
    {
        return "";
    }
    std::vector<BYTE> infoBuf;
    if (!CckyProbeAllocate<CryptDecodeObject, CckyProbeReturnPositive{}>(X509_ASN_ENCODING,
            SPC_SP_AGENCY_INFO_STRUCT, pExt->Value.pbData, pExt->Value.cbData, 0,
            CckyProbeBuffer(infoBuf), CckyProbeBytesRef<DWORD>()))
    {
        return "";
    }
    PSPC_SP_AGENCY_INFO pInfo = reinterpret_cast<PSPC_SP_AGENCY_INFO>(infoBuf.data());
    {
        return WinHelper::wideToUtf8(pInfo->pPolicyInformation->pwszUrl);
    }
    return "";
}

// Helpers
std::string Win32Cert::getNameDisplay(const CERT_NAME_BLOB* pNameBlob) const
{
    if (!pNameBlob || !pNameBlob->pbData || pNameBlob->cbData == 0)
    {
        return "";
    }

    DWORD cbInfo = 0;
    LocalFreePtr<CERT_NAME_INFO> pInfo;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_NAME, pNameBlob->pbData,
            pNameBlob->cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &pInfo.init(), &cbInfo))
    {
        return "";
    }

    std::stringstream ss;
    for (DWORD i = 0; i < pInfo->cRDN; ++i)
    {
        PCERT_RDN pRDN = &pInfo->rgRDN[i];
        for (DWORD j = 0; j < pRDN->cRDNAttr; ++j)
        {
            PCERT_RDN_ATTR pAttr = &pRDN->rgRDNAttr[j];
            ss << "[" << i << "," << j << "] ";
            if (pAttr->pszObjId)
            {
                ss << pAttr->pszObjId;
                PCCRYPT_OID_INFO pOidInfo =
                    CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pAttr->pszObjId, 0);
                if (pOidInfo && pOidInfo->pwszName)
                {
                    ss << " (" << WinHelper::wideToUtf8(pOidInfo->pwszName) << ")";
                }
            }
            std::wstring valBuf;
            DWORD cch = CckyProbeAllocate<CertRDNValueToStrW, CckyProbeReturnPositive{}>(
                pAttr->dwValueType, &pAttr->Value, CckyProbeBuffer(valBuf), CckyProbeSize{});
            if (cch > 0)
            {
                ss << " " << WinHelper::wideToUtf8(valBuf.c_str());
            }
            if (j + 1 < pRDN->cRDNAttr || i + 1 < pInfo->cRDN)
            {
                ss << "\n  ";
            }
        }
    }

    return ss.str();
}

std::string Win32Cert::getNameDN(const CERT_NAME_BLOB* pNameBlob) const
{
    if (!pNameBlob || !pNameBlob->pbData || pNameBlob->cbData == 0)
    {
        return "";
    }

    std::wstring wbuf;
    CckyProbeAllocate<CertNameToStrW, CckyProbeReturnPositive{}>(X509_ASN_ENCODING,
        const_cast<PCERT_NAME_BLOB>(pNameBlob), CERT_X500_NAME_STR, CckyProbeBuffer(wbuf),
        CckyProbeSize{});
    return WinHelper::wideToUtf8(wbuf.c_str());
}

Win32PfxCert::Win32PfxCert(CertContextPtr cert) : Win32Cert(std::move(cert)) {}

std::string Win32PfxCert::getProviderType() const { return "0"; }

std::string Win32PfxCert::getProviderName() const { return "PfxProvider"; }

std::string Win32PfxCert::getContainerName() const { return "PfxContainer"; }

Win32Crl::Win32Crl(CrlContextPtr crl) : m_crl(std::move(crl)) {}

std::string Win32Crl::getSha1() const
{
    if (m_crl == nullptr)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (!CertGetCRLContextProperty(m_crl.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::vector<uint8_t> Win32Crl::getEncoded() const
{
    if (m_crl == nullptr || !m_crl->pbCrlEncoded || m_crl->cbCrlEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(m_crl->pbCrlEncoded, m_crl->pbCrlEncoded + m_crl->cbCrlEncoded);
}

Win32Ctl::Win32Ctl(CtlContextPtr ctl) : m_ctl(std::move(ctl)) {}

std::string Win32Ctl::getSha1() const
{
    if (m_ctl == nullptr)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (!CertGetCTLContextProperty(m_ctl.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
    {
        return "";
    }
    std::stringstream ss;
    for (DWORD i = 0; i < len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::vector<uint8_t> Win32Ctl::getEncoded() const
{
    if (m_ctl == nullptr || !m_ctl->pbCtlEncoded || m_ctl->cbCtlEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(m_ctl->pbCtlEncoded, m_ctl->pbCtlEncoded + m_ctl->cbCtlEncoded);
}

} // namespace crypto
} // namespace ccky
