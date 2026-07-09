#include "crypto/windows/Win32Digest.h"

#include <fstream>
#include <iomanip>
#include <sstream>

#ifndef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#endif
#include <windows.h>

#include "crypto/Strings.h"
#include "crypto/windows/Win32Exception.h"
#include "crypto/windows/Win32Helper.h"

namespace ccky
{
namespace crypto
{

Win32DigestStream::Win32DigestStream(ALG_ID algId) : m_algId(algId)
{
    Win32Check::check(
        CryptAcquireContextW(&m_hProv.init(), nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT),
        "Failed to acquire crypto provider in Win32DigestStream");
    Win32Check::check(CryptCreateHash(m_hProv.get(), m_algId, 0, 0, &m_hHash.init()),
        "Failed to create hash object in Win32DigestStream");
}

void Win32DigestStream::update(const std::vector<uint8_t>& data)
{
    if (!data.empty())
    {
        Win32Check::check(
            CryptHashData(m_hHash.get(), data.data(), static_cast<DWORD>(data.size()), 0),
            "Failed to update hash in Win32DigestStream");
    }
}

std::vector<uint8_t> Win32DigestStream::calculateHash()
{
    CryptHashPtr hDup;
    Win32Check::check(CryptDuplicateHash(m_hHash.get(), nullptr, 0, &hDup.init()),
        "Failed to duplicate hash in Win32DigestStream");
    DWORD hashLen = 0;
    DWORD lenSize = sizeof(hashLen);
    Win32Check::check(
        CryptGetHashParam(hDup.get(), HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &lenSize, 0),
        "Failed to get hash size in Win32DigestStream");
    std::vector<uint8_t> hashBytes(hashLen);
    Win32Check::check(CryptGetHashParam(hDup.get(), HP_HASHVAL, hashBytes.data(), &hashLen, 0),
        "Failed to get hash value in Win32DigestStream");
    hashBytes.resize(hashLen);
    return hashBytes;
}

std::string Win32DigestStream::calculateHashString() { return Strings::hex(calculateHash()); }

Win32Digest::Win32Digest(ALG_ID algId) : m_algId(algId) {}

std::vector<uint8_t> Win32Digest::calculateHash(const std::vector<uint8_t>& data) const
{
    auto stream = createStream();
    stream->update(data);
    return stream->calculateHash();
}

std::vector<uint8_t> Win32Digest::calculateHash(const std::filesystem::path& path) const
{
    if (!std::filesystem::exists(path))
    {
        throw Win32Exception("File does not exist: " + path.string());
    }
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
    {
        throw Win32Exception("Failed to open file: " + path.string());
    }
    auto stream = createStream();
    std::vector<uint8_t> buf(65536);
    while (f.read(reinterpret_cast<char*>(buf.data()), buf.size()))
    {
        stream->update(buf);
    }
    if (f.gcount() > 0)
    {
        buf.resize(f.gcount());
        stream->update(buf);
    }
    return stream->calculateHash();
}

std::string Win32Digest::calculateHashString(const std::vector<uint8_t>& data) const
{
    return Strings::hex(calculateHash(data));
}

std::string Win32Digest::calculateHashString(const std::filesystem::path& path) const
{
    return Strings::hex(calculateHash(path));
}

DigestStreamPtr Win32Digest::createStream() const
{
    return std::make_unique<Win32DigestStream>(m_algId);
}

std::string Win32Digest::getName() const
{
    ALG_ID algId = m_algId;
    PCCRYPT_OID_INFO pInfo =
        CryptFindOIDInfo(CRYPT_OID_INFO_ALGID_KEY, &algId, CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr || pInfo->pwszName == nullptr)
    {
        throw Win32Exception("Unsupported digest algorithm ID: " + std::to_string(m_algId));
    }
    return Strings::toLower(Win32Helper::wideToUtf8(pInfo->pwszName));
}

std::string Win32Digest::getOid() const
{
    ALG_ID algId = m_algId;
    PCCRYPT_OID_INFO pInfo =
        CryptFindOIDInfo(CRYPT_OID_INFO_ALGID_KEY, &algId, CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr || pInfo->pszOID == nullptr)
    {
        throw Win32Exception("Unsupported digest algorithm ID: " + std::to_string(m_algId));
    }
    return pInfo->pszOID;
}

Win32CngDigestStream::Win32CngDigestStream(const std::wstring& cngAlgId) : m_cngAlgId(cngAlgId)
{
    Win32Check::checkStatus(
        BCryptOpenAlgorithmProvider(&m_hAlg.init(), m_cngAlgId.c_str(), nullptr, 0),
        "Failed to open algorithm provider in Win32CngDigestStream");

    DWORD objLen = 0;
    DWORD cbData = 0;
    Win32Check::checkStatus(BCryptGetProperty(m_hAlg.get(), BCRYPT_OBJECT_LENGTH,
                                reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbData, 0),
        "Failed to get object length in Win32CngDigestStream");

    m_hashObject.resize(objLen);

    Win32Check::checkStatus(BCryptCreateHash(m_hAlg.get(), &m_hHash.init(), m_hashObject.data(),
                                static_cast<ULONG>(m_hashObject.size()), nullptr, 0, 0),
        "Failed to create hash in Win32CngDigestStream");
}

void Win32CngDigestStream::update(const std::vector<uint8_t>& data)
{
    if (!data.empty())
    {
        Win32Check::checkStatus(BCryptHashData(m_hHash.get(), const_cast<PUCHAR>(data.data()),
                                    static_cast<ULONG>(data.size()), 0),
            "Failed to update hash in Win32CngDigestStream");
    }
}

std::vector<uint8_t> Win32CngDigestStream::calculateHash()
{
    BCryptHashHandlePtr hDup;
    std::vector<uint8_t> dupHashObject(m_hashObject.size());
    Win32Check::checkStatus(BCryptDuplicateHash(m_hHash.get(), &hDup.init(), dupHashObject.data(),
                                static_cast<ULONG>(dupHashObject.size()), 0),
        "Failed to duplicate hash in Win32CngDigestStream");

    DWORD hashLen = 0;
    DWORD cbData = 0;
    Win32Check::checkStatus(BCryptGetProperty(m_hAlg.get(), BCRYPT_HASH_LENGTH,
                                reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cbData, 0),
        "Failed to get hash length in Win32CngDigestStream");

    std::vector<uint8_t> hashBytes(hashLen);
    Win32Check::checkStatus(
        BCryptFinishHash(hDup.get(), hashBytes.data(), static_cast<ULONG>(hashBytes.size()), 0),
        "Failed to finish hash in Win32CngDigestStream");

    return hashBytes;
}

std::string Win32CngDigestStream::calculateHashString() { return Strings::hex(calculateHash()); }

Win32CngDigest::Win32CngDigest(ALG_ID algId, const std::wstring& cngAlgId)
    : Win32Digest(algId), m_cngAlgId(cngAlgId)
{
}

DigestStreamPtr Win32CngDigest::createStream() const
{
    return std::make_unique<Win32CngDigestStream>(m_cngAlgId);
}

std::string Win32CngDigest::getName() const
{
    PCCRYPT_OID_INFO pInfo = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY,
        const_cast<wchar_t*>(m_cngAlgId.c_str()), CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr || pInfo->pwszName == nullptr)
    {
        return Strings::toLower(Win32Helper::wideToUtf8(m_cngAlgId));
    }
    return Strings::toLower(Win32Helper::wideToUtf8(pInfo->pwszName));
}

std::string Win32CngDigest::getOid() const
{
    PCCRYPT_OID_INFO pInfo = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY,
        const_cast<wchar_t*>(m_cngAlgId.c_str()), CRYPT_HASH_ALG_OID_GROUP_ID);
    if (pInfo == nullptr || pInfo->pszOID == nullptr)
    {
        throw Win32Exception(
            "Unsupported CNG digest OID for: " + Win32Helper::wideToUtf8(m_cngAlgId));
    }
    return pInfo->pszOID;
}

} // namespace crypto
} // namespace ccky
