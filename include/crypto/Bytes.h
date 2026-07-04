#ifndef CCKY_CRYPTO_BYTES_H
#define CCKY_CRYPTO_BYTES_H

#include <cstdint>

namespace ccky
{
namespace crypto
{

class Bytes
{
  public:
    static inline uint32_t readU32LE(const uint8_t* p)
    {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    }
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_BYTES_H
