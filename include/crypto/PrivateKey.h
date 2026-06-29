#ifndef CCKY_PRIVATE_KEY_H
#define CCKY_PRIVATE_KEY_H

#include <memory>
#include <string>

namespace ccky
{
namespace crypto
{

class PrivateKey
{
  public:
    virtual ~PrivateKey() = default;

    virtual std::string getContainerName() const = 0;
    virtual std::string getProviderName() const = 0;
    virtual uint32_t getProviderType() const = 0;
    virtual uint32_t getKeySpec() const = 0;
};

using PrivateKeyPtr = std::shared_ptr<PrivateKey>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_PRIVATE_KEY_H
