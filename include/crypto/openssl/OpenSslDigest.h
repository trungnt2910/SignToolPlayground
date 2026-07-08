#ifndef CCKY_CRYPTO_OPENSSL_DIGEST_H
#define CCKY_CRYPTO_OPENSSL_DIGEST_H

#include <openssl/evp.h>

#include "crypto/Digest.h"
#include "crypto/openssl/OpenSslWrapper.h"

namespace ccky
{
namespace crypto
{

class OpenSslDigestStream : public DigestStream
{
  public:
    explicit OpenSslDigestStream(const EVP_MD* md);
    ~OpenSslDigestStream() override = default;

    void update(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> calculateHash() override;
    std::string calculateHashString() override;

  private:
    EVPMDCtxPtr m_ctx;
    const EVP_MD* m_md;
};

class OpenSslDigest : public Digest
{
  public:
    explicit OpenSslDigest(int nid);
    ~OpenSslDigest() override = default;

    std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data) const override;
    std::vector<uint8_t> calculateHash(const std::filesystem::path& path) const override;

    std::string calculateHashString(const std::vector<uint8_t>& data) const override;
    std::string calculateHashString(const std::filesystem::path& path) const override;

    DigestStreamPtr createStream() const override;

    std::string getName() const override;
    std::string getOid() const override;

    int getInternal() const { return m_nid; }

  private:
    int m_nid;
    const EVP_MD* getMd() const;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_OPENSSL_DIGEST_H
