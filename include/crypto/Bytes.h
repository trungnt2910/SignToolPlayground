#ifndef CCKY_CRYPTO_BYTES_H
#define CCKY_CRYPTO_BYTES_H

#include <array>
#include <cstdint>
#include <iostream>
#include <type_traits>
#include <vector>

namespace ccky
{
namespace crypto
{

class Bytes
{
  public:
    static inline uint16_t readU16LE(const uint8_t* p)
    {
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    }

    static inline uint32_t readU32LE(const uint8_t* p)
    {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    }

    static inline uint64_t readU64LE(const uint8_t* p)
    {
        return static_cast<uint64_t>(readU32LE(p)) |
               (static_cast<uint64_t>(readU32LE(p + 4)) << 32);
    }

    static inline void writeU16LE(uint16_t val, uint8_t* p)
    {
        p[0] = static_cast<uint8_t>(val & 0xFF);
        p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    }

    static inline void writeU32LE(uint32_t val, uint8_t* p)
    {
        p[0] = static_cast<uint8_t>(val & 0xFF);
        p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        p[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    }

    static inline void writeU64LE(uint64_t val, uint8_t* p)
    {
        writeU32LE(static_cast<uint32_t>(val & 0xFFFFFFFF), p);
        writeU32LE(static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF), p + 4);
    }

    static inline void appendU16LE(std::vector<uint8_t>& buf, uint16_t val)
    {
        size_t oldSize = buf.size();
        buf.resize(oldSize + 2);
        writeU16LE(val, &buf[oldSize]);
    }

    static inline void appendU32LE(std::vector<uint8_t>& buf, uint32_t val)
    {
        size_t oldSize = buf.size();
        buf.resize(oldSize + 4);
        writeU32LE(val, &buf[oldSize]);
    }

    static inline void appendU64LE(std::vector<uint8_t>& buf, uint64_t val)
    {
        size_t oldSize = buf.size();
        buf.resize(oldSize + 8);
        writeU64LE(val, &buf[oldSize]);
    }

    template <typename T> struct LEWrapper
    {
        T val;
    };

    static inline LEWrapper<uint16_t&> U16LE(uint16_t& var) { return {var}; }
    static inline LEWrapper<uint16_t> U16LE(const uint16_t& val) { return {val}; }

    static inline LEWrapper<uint32_t&> U32LE(uint32_t& var) { return {var}; }
    static inline LEWrapper<uint32_t> U32LE(const uint32_t& val) { return {val}; }

    static inline LEWrapper<uint64_t&> U64LE(uint64_t& var) { return {var}; }
    static inline LEWrapper<uint64_t> U64LE(const uint64_t& val) { return {val}; }
};

template <typename T>
inline std::istream& operator>>(std::istream& is, const Bytes::LEWrapper<T>& w)
{
    constexpr size_t size = sizeof(std::remove_reference_t<T>);
    std::array<uint8_t, size> buf;
    if (!is.read(reinterpret_cast<char*>(buf.data()), size))
    {
        return is;
    }

    if constexpr (size == sizeof(uint16_t))
    {
        w.val = Bytes::readU16LE(buf.data());
    }
    else if constexpr (size == sizeof(uint32_t))
    {
        w.val = Bytes::readU32LE(buf.data());
    }
    else if constexpr (size == sizeof(uint64_t))
    {
        w.val = Bytes::readU64LE(buf.data());
    }
    return is;
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const Bytes::LEWrapper<T>& w)
{
    constexpr size_t size = sizeof(std::remove_reference_t<T>);
    std::array<uint8_t, size> buf;
    if constexpr (size == sizeof(uint16_t))
    {
        Bytes::writeU16LE(w.val, buf.data());
    }
    else if constexpr (size == sizeof(uint32_t))
    {
        Bytes::writeU32LE(w.val, buf.data());
    }
    else if constexpr (size == sizeof(uint64_t))
    {
        Bytes::writeU64LE(w.val, buf.data());
    }
    os.write(reinterpret_cast<const char*>(buf.data()), size);
    return os;
}

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_BYTES_H
