#ifndef CCKY_CRYPTO_DIGEST_H
#define CCKY_CRYPTO_DIGEST_H

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace ccky
{
namespace crypto
{

class DigestStream
{
  public:
    virtual ~DigestStream() = default;
    virtual void update(const std::vector<uint8_t>& data) = 0;

    DigestStream& operator<<(const std::vector<uint8_t>& data)
    {
        update(data);
        return *this;
    }

    virtual std::vector<uint8_t> calculateHash() = 0;
    virtual std::string calculateHashString() = 0;
};

using DigestStreamPtr = std::unique_ptr<DigestStream>;

class Digest
{
  public:
    virtual ~Digest() = default;

    virtual std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data) const = 0;
    virtual std::vector<uint8_t> calculateHash(const std::filesystem::path& path) const = 0;

    virtual std::string calculateHashString(const std::vector<uint8_t>& data) const = 0;
    virtual std::string calculateHashString(const std::filesystem::path& path) const = 0;

    virtual DigestStreamPtr createStream() const = 0;

    virtual std::string getName() const = 0;
    virtual std::string getOid() const = 0;
};

using DigestPtr = std::shared_ptr<Digest>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_DIGEST_H
