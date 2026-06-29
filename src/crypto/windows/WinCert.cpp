#include "crypto/windows/WinCert.h"
#include "crypto/windows/WinHelper.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#include <wintrust.h>

#include "crypto/TimeFormatter.h"

namespace ccky
{
namespace crypto
{

WinCert::WinCert(PCCERT_CONTEXT cert)
{
    if (cert)
    {
        m_cert.reset(CertDuplicateCertificateContext(cert));
    }
}

std::string WinCert::getCommonName() const
{
    if (!m_cert)
    {
        return "";
    }
    char buf[256] = {0};
    DWORD len = CertGetNameStringA(
        m_cert.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, sizeof(buf));
    if (len > 1)
    {
        return std::string(buf);
    }
    return "";
}

std::string WinCert::getIssuerName() const
{
    if (!m_cert)
    {
        return "";
    }
    char buf[256] = {0};
    DWORD len = CertGetNameStringA(m_cert.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG, nullptr, buf, sizeof(buf));
    if (len > 1)
    {
        return std::string(buf);
    }
    return "";
}

std::string WinCert::getSha1() const
{
    if (!m_cert)
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

std::vector<uint8_t> WinCert::getEncoded() const
{
    if (!m_cert || !m_cert->pbCertEncoded || m_cert->cbCertEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(
        m_cert->pbCertEncoded, m_cert->pbCertEncoded + m_cert->cbCertEncoded);
}

std::string WinCert::getNameDisplay(const CERT_NAME_BLOB* pNameBlob) const
{
    if (!pNameBlob || !pNameBlob->pbData || pNameBlob->cbData == 0)
    {
        return "";
    }

    DWORD cbInfo = 0;
    PCERT_NAME_INFO rawInfo = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_NAME, pNameBlob->pbData,
            pNameBlob->cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &rawInfo, &cbInfo))
    {
        return "";
    }
    LocalFreePtr<CERT_NAME_INFO> pInfo(rawInfo);

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
            DWORD cch = CertRDNValueToStrA(pAttr->dwValueType, &pAttr->Value, nullptr, 0);
            if (cch > 0)
            {
                std::vector<char> valBuf(cch);
                CertRDNValueToStrA(pAttr->dwValueType, &pAttr->Value, valBuf.data(), cch);
                ss << " " << valBuf.data();
            }
            if (j + 1 < pRDN->cRDNAttr || i + 1 < pInfo->cRDN)
            {
                ss << "\n  ";
            }
        }
    }

    return ss.str();
}

std::string WinCert::getSubjectDisplay() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDisplay(&m_cert->pCertInfo->Subject);
}

std::string WinCert::getIssuerDisplay() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDisplay(&m_cert->pCertInfo->Issuer);
}

std::string WinCert::getNameDN(const CERT_NAME_BLOB* pNameBlob) const
{
    if (!pNameBlob || !pNameBlob->pbData || pNameBlob->cbData == 0)
    {
        return "";
    }

    DWORD cch = CertNameToStrA(
        X509_ASN_ENCODING, const_cast<PCERT_NAME_BLOB>(pNameBlob), CERT_X500_NAME_STR, nullptr, 0);
    if (cch <= 1)
    {
        return "";
    }

    std::vector<char> buf(cch);
    CertNameToStrA(X509_ASN_ENCODING, const_cast<PCERT_NAME_BLOB>(pNameBlob), CERT_X500_NAME_STR,
        buf.data(), cch);
    return std::string(buf.data());
}

std::string WinCert::getSubjectDN() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDN(&m_cert->pCertInfo->Subject);
}

std::string WinCert::getIssuerDN() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    return getNameDN(&m_cert->pCertInfo->Issuer);
}
std::string WinCert::getSerialNumber() const
{
    if (!m_cert || !m_cert->pCertInfo)
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
std::string WinCert::getSha1Thumbprint() const
{
    if (!m_cert)
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
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(hash[i]);
            if ((i % 4 == 3) && (i + 1 < len))
            {
                ss << " ";
            }
        }
        return ss.str();
    }
    return "";
}
std::string WinCert::getMd5Thumbprint() const
{
    if (!m_cert)
    {
        return "";
    }
    BYTE hash[16];
    DWORD len = sizeof(hash);
    if (CertGetCertificateContextProperty(m_cert.get(), CERT_MD5_HASH_PROP_ID, hash, &len))
    {
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
    return "";
}
std::string WinCert::getKeyMd5Thumbprint() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }

    DWORD derSize = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &m_cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, nullptr, &derSize) ||
        derSize == 0)
    {
        return "";
    }

    std::vector<BYTE> der(derSize);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &m_cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, der.data(), &derSize))
    {
        return "";
    }

    HCRYPTPROV rawProv = 0;
    if (CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptProvPtr hProv(rawProv);
        HCRYPTHASH rawHash = 0;
        if (CryptCreateHash(hProv.get(), CALG_MD5, 0, 0, &rawHash))
        {
            CryptHashPtr hHash(rawHash);
            if (CryptHashData(hHash.get(), der.data(), derSize, 0))
            {
                BYTE hash[16];
                DWORD len = sizeof(hash);
                if (CryptGetHashParam(hHash.get(), HP_HASHVAL, hash, &len, 0))
                {
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
            }
        }
    }
    return "";
}
std::string WinCert::getProviderType() const
{
    if (!m_cert)
    {
        return "";
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size))
    {
        std::vector<uint8_t> buf(size);
        if (CertGetCertificateContextProperty(
                m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
        {
            auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
            return std::to_string(info->dwProvType);
        }
    }
    return "";
}
std::string WinCert::getProviderName() const
{
    if (!m_cert)
    {
        return "";
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size))
    {
        std::vector<uint8_t> buf(size);
        if (CertGetCertificateContextProperty(
                m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
        {
            auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
            if (info->pwszProvName)
            {
                return WinHelper::wideToUtf8(info->pwszProvName);
            }
        }
    }
    return "";
}
std::string WinCert::getContainerName() const
{
    if (!m_cert)
    {
        return "";
    }
    DWORD size = 0;
    if (CertGetCertificateContextProperty(m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size))
    {
        std::vector<uint8_t> buf(size);
        if (CertGetCertificateContextProperty(
                m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
        {
            auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
            if (info->pwszContainerName)
            {
                return WinHelper::wideToUtf8(info->pwszContainerName);
            }
        }
    }
    return "";
}
std::string WinCert::getNotBefore() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    uint64_t intervals =
        (static_cast<uint64_t>(m_cert->pCertInfo->NotBefore.dwHighDateTime) << 32) |
        m_cert->pCertInfo->NotBefore.dwLowDateTime;
    time_t time = static_cast<time_t>((intervals / 10000000ULL) - 11644473600ULL);
    auto tp = std::chrono::system_clock::from_time_t(time);
    return TimeFormatter::formatTime(tp);
}
std::string WinCert::getNotAfter() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    uint64_t intervals = (static_cast<uint64_t>(m_cert->pCertInfo->NotAfter.dwHighDateTime) << 32) |
                         m_cert->pCertInfo->NotAfter.dwLowDateTime;
    time_t time = static_cast<time_t>((intervals / 10000000ULL) - 11644473600ULL);
    auto tp = std::chrono::system_clock::from_time_t(time);
    return TimeFormatter::formatTime(tp);
}

bool WinCert::isCA() const
{
    if (!m_cert || !m_cert->pCertInfo)
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

int WinCert::getPathLenConstraint() const
{
    if (!m_cert || !m_cert->pCertInfo)
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

int WinCert::getKeyLength() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return 0;
    }
    return CertGetPublicKeyLength(X509_ASN_ENCODING, &m_cert->pCertInfo->SubjectPublicKeyInfo);
}

std::vector<std::string> WinCert::getEnhancedKeyUsage() const
{
    std::vector<std::string> res;
    if (!m_cert)
    {
        return res;
    }
    DWORD cbUsage = 0;
    if (!CertGetEnhancedKeyUsage(m_cert.get(), 0, nullptr, &cbUsage))
    {
        return res;
    }
    std::vector<BYTE> usageBuf(cbUsage);
    PCERT_ENHKEY_USAGE pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(usageBuf.data());
    if (!CertGetEnhancedKeyUsage(m_cert.get(), 0, pUsage, &cbUsage))
    {
        return res;
    }
    for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i)
    {
        res.push_back(pUsage->rgpszUsageIdentifier[i]);
    }
    return res;
}

std::string WinCert::getSignatureAlgorithm() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    return m_cert->pCertInfo->SignatureAlgorithm.pszObjId;
}

uint32_t WinCert::getNetscapeCertType() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return 0;
    }
    PCERT_EXTENSION pExt = CertFindExtension(
        szOID_NETSCAPE_CERT_TYPE, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!pExt)
    {
        return 0;
    }
    DWORD cbBits = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_BITS, pExt->Value.pbData, pExt->Value.cbData, 0,
            nullptr, &cbBits))
    {
        return 0;
    }
    std::vector<BYTE> bitsBuf(cbBits);
    PCRYPT_BIT_BLOB pBits = reinterpret_cast<PCRYPT_BIT_BLOB>(bitsBuf.data());
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_BITS, pExt->Value.pbData, pExt->Value.cbData, 0,
            pBits, &cbBits))
    {
        return 0;
    }
    if (pBits->cbData > 0)
    {
        return pBits->pbData[0];
    }
    return 0;
}

std::string WinCert::getKeySha256Thumbprint() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    DWORD cbEncoded = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &m_cert->pCertInfo->SubjectPublicKeyInfo, nullptr, &cbEncoded))
    {
        return "";
    }
    std::vector<BYTE> encodedBuf(cbEncoded);
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &m_cert->pCertInfo->SubjectPublicKeyInfo, encodedBuf.data(), &cbEncoded))
    {
        return "";
    }

    HCRYPTPROV rawProv = 0;
    if (!CryptAcquireContextW(&rawProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return "";
    }
    CryptProvPtr hProv(rawProv);
    HCRYPTHASH rawHash = 0;
    if (!CryptCreateHash(hProv.get(), CALG_SHA_256, 0, 0, &rawHash))
    {
        return "";
    }
    CryptHashPtr hHash(rawHash);
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

bool WinCert::isPrivateKeyExportable() const
{
    if (!m_cert)
    {
        return false;
    }
    DWORD size = 0;
    if (!CertGetCertificateContextProperty(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size))
    {
        return false;
    }
    std::vector<uint8_t> buf(size);
    if (!CertGetCertificateContextProperty(
            m_cert.get(), CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &size))
    {
        return false;
    }
    auto* info = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(buf.data());
    HCRYPTPROV rawProv = 0;
    if (!CryptAcquireContextW(
            &rawProv, info->pwszContainerName, info->pwszProvName, info->dwProvType, 0))
    {
        return false;
    }
    CryptProvPtr hProv(rawProv);
    HCRYPTKEY rawKey = 0;
    DWORD keySpec = info->dwKeySpec;
    if (!CryptGetUserKey(hProv.get(), keySpec, &rawKey))
    {
        if (!CryptGetUserKey(hProv.get(), AT_KEYEXCHANGE, &rawKey))
        {
            if (!CryptGetUserKey(hProv.get(), AT_SIGNATURE, &rawKey))
            {
                return false;
            }
        }
    }
    CryptKeyPtr hKey(rawKey);
    DWORD exportSize = 0;
    if (CryptExportKey(hKey.get(), 0, PRIVATEKEYBLOB, 0, nullptr, &exportSize))
    {
        return true;
    }
    return false;
}

std::string WinCert::getPolicyLink() const
{
    if (!m_cert || !m_cert->pCertInfo)
    {
        return "";
    }
    PCERT_EXTENSION pExt = CertFindExtension(
        SPC_SP_AGENCY_INFO_OBJID, m_cert->pCertInfo->cExtension, m_cert->pCertInfo->rgExtension);
    if (!pExt)
    {
        return "";
    }
    DWORD cbInfo = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, SPC_SP_AGENCY_INFO_STRUCT, pExt->Value.pbData,
            pExt->Value.cbData, 0, nullptr, &cbInfo))
    {
        return "";
    }
    std::vector<BYTE> infoBuf(cbInfo);
    PSPC_SP_AGENCY_INFO pInfo = reinterpret_cast<PSPC_SP_AGENCY_INFO>(infoBuf.data());
    if (!CryptDecodeObject(X509_ASN_ENCODING, SPC_SP_AGENCY_INFO_STRUCT, pExt->Value.pbData,
            pExt->Value.cbData, 0, pInfo, &cbInfo))
    {
        return "";
    }
    if (pInfo->pPolicyInformation && pInfo->pPolicyInformation->dwLinkChoice == SPC_URL_LINK_CHOICE)
    {
        return WinHelper::wideToUtf8(pInfo->pPolicyInformation->pwszUrl);
    }
    return "";
}

WinPfxCert::WinPfxCert(PCCERT_CONTEXT cert) : WinCert(cert) {}
std::string WinPfxCert::getProviderType() const { return "0"; }
std::string WinPfxCert::getProviderName() const { return "PfxProvider"; }
std::string WinPfxCert::getContainerName() const { return "PfxContainer"; }

WinCrl::WinCrl(PCCRL_CONTEXT crl)
{
    if (crl)
    {
        m_crl.reset(CertDuplicateCRLContext(crl));
    }
}

std::string WinCrl::getSha1() const
{
    if (!m_crl)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (CertGetCRLContextProperty(m_crl.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
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

std::vector<uint8_t> WinCrl::getEncoded() const
{
    if (!m_crl || !m_crl->pbCrlEncoded || m_crl->cbCrlEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(m_crl->pbCrlEncoded, m_crl->pbCrlEncoded + m_crl->cbCrlEncoded);
}

WinCtl::WinCtl(PCCTL_CONTEXT ctl)
{
    if (ctl)
    {
        m_ctl.reset(CertDuplicateCTLContext(ctl));
    }
}

std::string WinCtl::getSha1() const
{
    if (!m_ctl)
    {
        return "";
    }
    BYTE hash[20];
    DWORD len = sizeof(hash);
    if (CertGetCTLContextProperty(m_ctl.get(), CERT_SHA1_HASH_PROP_ID, hash, &len))
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

std::vector<uint8_t> WinCtl::getEncoded() const
{
    if (!m_ctl || !m_ctl->pbCtlEncoded || m_ctl->cbCtlEncoded == 0)
    {
        return {};
    }
    return std::vector<uint8_t>(m_ctl->pbCtlEncoded, m_ctl->pbCtlEncoded + m_ctl->cbCtlEncoded);
}

} // namespace crypto
} // namespace ccky
