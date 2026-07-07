#include "crypto/PvkKey.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

#include "crypto/Bytes.h"
#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"

namespace ccky
{
namespace crypto
{

namespace
{
constexpr uint32_t PVK_MAGIC = 0xB0B5F11E;
constexpr size_t PVK_PUBLIC_KEY_SIZE = 8;
constexpr uint32_t PVK_RSAPUBLIC_MAGIC = 0x31415352;  // 'RSA1'
constexpr uint32_t PVK_RSAPRIVATE_MAGIC = 0x32415352; // 'RSA2'
constexpr uint8_t PVK_BLOB_VERSION = 2;

struct PvkHeader
{
    uint32_t magic;
    uint32_t reserved;
    uint32_t keyType;
    uint32_t encrypted;
    uint32_t saltLen;
    uint32_t keyLen;
};

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

PvkKey::PvkKey() : m_keyType(PvkKeySpec::KeyExchange), m_isEncrypted(false) {}
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

    PvkHeader header;
    if (!(file >> Bytes::U32LE(header.magic) >> Bytes::U32LE(header.reserved) >>
            Bytes::U32LE(header.keyType) >> Bytes::U32LE(header.encrypted) >>
            Bytes::U32LE(header.saltLen) >> Bytes::U32LE(header.keyLen)))
    {
        throw PvkCorruptFileException("Failed to read PVK header: " + filePath);
    }

    if (header.magic != PVK_MAGIC)
    {
        throw PvkCorruptFileException("Invalid PVK magic: " + filePath);
    }

    m_keyType = static_cast<PvkKeySpec>(header.keyType);
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

    if (m_payload.size() < PVK_PUBLIC_KEY_SIZE)
    {
        throw PvkCorruptFileException("PVK key payload too small: " + filePath);
    }

    uint8_t bVersion = m_payload[1];
    if (bVersion != PVK_BLOB_VERSION)
    {
        throw PvkBadProviderVersionException("Bad Version of provider");
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

    if (m_payload.size() < PVK_PUBLIC_KEY_SIZE)
    {
        throw PvkCorruptFileException("Payload too small");
    }

    std::vector<uint8_t> rc4Key = deriveRc4Key(password, m_salt);

    std::vector<uint8_t> encryptedPart(m_payload.begin() + PVK_PUBLIC_KEY_SIZE, m_payload.end());
    std::vector<uint8_t> decryptedPart = CryptoFactory::encryptRc4Bytes(rc4Key, encryptedPart);

    m_keyData.clear();
    m_keyData.reserve(m_payload.size());
    m_keyData.insert(m_keyData.end(), m_payload.begin(), m_payload.begin() + PVK_PUBLIC_KEY_SIZE);
    m_keyData.insert(m_keyData.end(), decryptedPart.begin(), decryptedPart.end());

    // Validate by checking the RSA2 magic in the PRIVATEKEYBLOB
    // PRIVATEKEYBLOB starts with:
    // BYTE bType; (0x07 for PRIVATEKEYBLOB)
    // BYTE bVersion; (0x02)
    // WORD reserved;
    // ALG_ID aiKeyAlg;
    // DWORD magic; (RSA2)
    if (m_keyData.size() >= PVK_PUBLIC_KEY_SIZE + 4)
    {
        uint32_t rsaMagic = Bytes::readU32LE(m_keyData.data() + PVK_PUBLIC_KEY_SIZE);
        if (rsaMagic != PVK_RSAPRIVATE_MAGIC)
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

void PvkKey::encrypt(const std::string& password, const std::vector<uint8_t>& salt)
{
    if (password.empty())
    {
        m_isEncrypted = false;
        m_salt.clear();
        m_payload = m_keyData;
        return;
    }

    if (m_keyData.size() < PVK_PUBLIC_KEY_SIZE)
    {
        throw std::runtime_error("Key data too small to encrypt");
    }

    m_isEncrypted = true;
    if (!salt.empty())
    {
        m_salt = salt;
    }
    else
    {
        m_salt.resize(16); // Generate 16 bytes of salt
        CryptoFactory::getRandomBytes(m_salt.data(), m_salt.size());
    }

    std::vector<uint8_t> rc4Key = deriveRc4Key(password, m_salt);

    std::vector<uint8_t> plainPart(m_keyData.begin() + PVK_PUBLIC_KEY_SIZE, m_keyData.end());
    std::vector<uint8_t> encryptedPart = CryptoFactory::encryptRc4Bytes(rc4Key, plainPart);

    m_payload.clear();
    m_payload.reserve(m_keyData.size());
    m_payload.insert(m_payload.end(), m_keyData.begin(), m_keyData.begin() + PVK_PUBLIC_KEY_SIZE);
    m_payload.insert(m_payload.end(), encryptedPart.begin(), encryptedPart.end());
}

void PvkKey::setKeyData(const std::vector<uint8_t>& keyData, PvkKeySpec keyType)
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

    file << Bytes::U32LE(static_cast<uint32_t>(PVK_MAGIC)) << Bytes::U32LE(0U)
         << Bytes::U32LE(static_cast<uint32_t>(m_keyType)) << Bytes::U32LE(m_isEncrypted ? 1U : 0U)
         << Bytes::U32LE(static_cast<uint32_t>(m_salt.size()))
         << Bytes::U32LE(static_cast<uint32_t>(m_payload.size()));
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
