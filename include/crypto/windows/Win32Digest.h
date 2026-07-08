#ifndef CCKY_CRYPTO_WINDOWS_DIGEST_H
#define CCKY_CRYPTO_WINDOWS_DIGEST_H

#ifndef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#endif

#include <windows.h>

#include <bcrypt.h>
#include <wincrypt.h>

#include "crypto/Digest.h"
#include "crypto/windows/Win32Wrapper.h"

namespace ccky
{
namespace crypto
{

class Win32DigestStream : public DigestStream
{
  public:
    explicit Win32DigestStream(ALG_ID algId);
    ~Win32DigestStream() override = default;

    void update(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> calculateHash() override;
    std::string calculateHashString() override;

  private:
    ALG_ID m_algId;
    CryptProvPtr m_hProv;
    CryptHashPtr m_hHash;
};

class Win32Digest : public Digest
{
  public:
    explicit Win32Digest(ALG_ID algId);
    ~Win32Digest() override = default;

    std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data) const override;
    std::vector<uint8_t> calculateHash(const std::filesystem::path& path) const override;

    std::string calculateHashString(const std::vector<uint8_t>& data) const override;
    std::string calculateHashString(const std::filesystem::path& path) const override;

    DigestStreamPtr createStream() const override;

    std::string getName() const override;
    std::string getOid() const override;

    ALG_ID getInternal() const { return m_algId; }

  private:
    ALG_ID m_algId;
};

class Win32CngDigestStream : public DigestStream
{
  public:
    explicit Win32CngDigestStream(const std::wstring& cngAlgId);
    ~Win32CngDigestStream() override = default;

    void update(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> calculateHash() override;
    std::string calculateHashString() override;

  private:
    std::wstring m_cngAlgId;
    BCryptAlgHandlePtr m_hAlg;
    BCryptHashHandlePtr m_hHash;
    std::vector<uint8_t> m_hashObject;
};

class Win32CngDigest : public Win32Digest
{
  public:
    Win32CngDigest(ALG_ID algId, const std::wstring& cngAlgId);
    ~Win32CngDigest() override = default;

    DigestStreamPtr createStream() const override;

    std::string getName() const override;
    std::string getOid() const override;

  private:
    std::wstring m_cngAlgId;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_WINDOWS_DIGEST_H
