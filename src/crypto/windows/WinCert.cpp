#include "crypto/windows/WinCert.h"

#include <chrono>
#include <iomanip>
#include <sstream>

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
                    std::wstring wName(pOidInfo->pwszName);
                    ss << " (" << std::string(wName.begin(), wName.end()) << ")";
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
                std::wstring wstr(info->pwszProvName);
                return std::string(wstr.begin(), wstr.end());
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
                std::wstring wstr(info->pwszContainerName);
                return std::string(wstr.begin(), wstr.end());
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
