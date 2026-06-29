#include "crypto/PvkKey.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"

namespace ccky
{
namespace crypto
{

namespace
{
constexpr uint32_t PVK_MAGIC = 0xB0B5F11E;

struct PvkHeader
{
    uint32_t magic;
    uint32_t reserved;
    uint32_t keyType;
    uint32_t encrypted;
    uint32_t saltLen;
    uint32_t keyLen;
};

uint32_t readU32LE(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void writeU32LE(uint32_t val, uint8_t* p)
{
    p[0] = static_cast<uint8_t>(val & 0xFF);
    p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

std::vector<uint8_t> deriveRc4Key(const std::string& password, const std::vector<uint8_t>& salt)
{
    std::vector<uint8_t> block;
    block.reserve(salt.size() + password.size());
    block.insert(block.end(), salt.begin(), salt.end());
    block.insert(block.end(), password.begin(), password.end());

    std::vector<uint8_t> hash = CryptoFactory::calculateSha1Bytes(block);
    hash.resize(16); // take first 16 bytes
    return hash;
}

} // namespace

PvkKey::PvkKey() : m_keyType(0), m_isEncrypted(false) {}
PvkKey::~PvkKey() = default;
PvkKey::PvkKey(PvkKey&& other) noexcept = default;
PvkKey& PvkKey::operator=(PvkKey&& other) noexcept = default;

void PvkKey::load(const std::string& filePath)
{
    if (!std::filesystem::exists(filePath))
    {
        throw FileNotFoundException("PVK file does not exist: " + filePath);
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        throw PvkCorruptFileException("Failed to open PVK file: " + filePath);
    }

    uint8_t headerBuf[24];
    if (!file.read(reinterpret_cast<char*>(headerBuf), 24))
    {
        throw PvkCorruptFileException("Failed to read PVK header: " + filePath);
    }

    PvkHeader header;
    header.magic = readU32LE(headerBuf);
    header.reserved = readU32LE(headerBuf + 4);
    header.keyType = readU32LE(headerBuf + 8);
    header.encrypted = readU32LE(headerBuf + 12);
    header.saltLen = readU32LE(headerBuf + 16);
    header.keyLen = readU32LE(headerBuf + 20);

    if (header.magic != PVK_MAGIC)
    {
        throw PvkCorruptFileException("Invalid PVK magic: " + filePath);
    }

    m_keyType = header.keyType;
    m_isEncrypted = (header.encrypted != 0);

    m_salt.resize(header.saltLen);
    if (header.saltLen > 0 && !file.read(reinterpret_cast<char*>(m_salt.data()), header.saltLen))
    {
        throw PvkCorruptFileException("Failed to read PVK salt: " + filePath);
    }

    m_payload.resize(header.keyLen);
    if (header.keyLen > 0 && !file.read(reinterpret_cast<char*>(m_payload.data()), header.keyLen))
    {
        throw PvkCorruptFileException("Failed to read PVK key payload: " + filePath);
    }

    if (!m_isEncrypted)
    {
        m_keyData = m_payload;
    }
}

void PvkKey::decrypt(const std::string& password)
{
    if (!m_isEncrypted)
    {
        m_keyData = m_payload;
        return; // Nothing to decrypt
    }

    std::vector<uint8_t> rc4Key = deriveRc4Key(password, m_salt);

    m_keyData = CryptoFactory::encryptRc4Bytes(rc4Key, m_payload);

    // Validate by checking the RSA2 magic in the PRIVATEKEYBLOB
    // PRIVATEKEYBLOB starts with:
    // BYTE bType; (0x07 for PRIVATEKEYBLOB)
    // BYTE bVersion; (0x02)
    // WORD reserved;
    // ALG_ID aiKeyAlg;
    // DWORD magic; (RSA2)
    if (m_keyData.size() >= 12)
    {
        uint32_t rsaMagic = readU32LE(m_keyData.data() + 8);
        if (rsaMagic != 0x32415352) // "RSA2"
        {
            // Clear wrong key data
            for (auto& b : m_keyData)
            {
                b = 0;
            }
            m_keyData.clear();
            throw PvkIncorrectPasswordException("Incorrect password for PVK file");
        }
    }
    else
    {
        throw PvkCorruptFileException("Decrypted payload too small to be a PRIVATEKEYBLOB");
    }
}

void PvkKey::encrypt(const std::string& password)
{
    if (password.empty())
    {
        m_isEncrypted = false;
        m_salt.clear();
        m_payload = m_keyData;
        return;
    }

    m_isEncrypted = true;
    m_salt.resize(16); // Generate 16 bytes of salt

    CryptoFactory::getRandomBytes(m_salt.data(), m_salt.size());

    std::vector<uint8_t> rc4Key = deriveRc4Key(password, m_salt);

    m_payload = CryptoFactory::encryptRc4Bytes(rc4Key, m_keyData);
}

void PvkKey::setKeyData(const std::vector<uint8_t>& keyData, uint32_t keyType)
{
    m_keyData = keyData;
    m_keyType = keyType;
    m_payload = keyData;
    m_isEncrypted = false;
    m_salt.clear();
}

void PvkKey::save(const std::string& filePath) const
{
    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open PVK file for writing: " + filePath);
    }

    uint8_t headerBuf[24];
    writeU32LE(PVK_MAGIC, headerBuf);
    writeU32LE(0, headerBuf + 4);
    writeU32LE(m_keyType, headerBuf + 8);
    writeU32LE(m_isEncrypted ? 1 : 0, headerBuf + 12);
    writeU32LE(static_cast<uint32_t>(m_salt.size()), headerBuf + 16);
    writeU32LE(static_cast<uint32_t>(m_payload.size()), headerBuf + 20);

    file.write(reinterpret_cast<const char*>(headerBuf), 24);
    if (!m_salt.empty())
    {
        file.write(reinterpret_cast<const char*>(m_salt.data()), m_salt.size());
    }
    if (!m_payload.empty())
    {
        file.write(reinterpret_cast<const char*>(m_payload.data()), m_payload.size());
    }
}

} // namespace crypto
} // namespace ccky
