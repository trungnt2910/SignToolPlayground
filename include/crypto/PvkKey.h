#ifndef CCKY_CRYPTO_PVK_KEY_H
#define CCKY_CRYPTO_PVK_KEY_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

class PvkCorruptFileException : public CckyException
{
  public:
    PvkCorruptFileException(const std::string& msg) : CckyException(msg, false) {}
};

class PvkIncorrectPasswordException : public CckyException
{
  public:
    PvkIncorrectPasswordException(const std::string& msg) : CckyException(msg, false) {}
};

class PvkBadProviderVersionException : public CckyException
{
  public:
    PvkBadProviderVersionException(const std::string& msg) : CckyException(msg, false) {}
};

enum class PvkKeySpec : uint32_t
{
    KeyExchange = 1, // AT_KEYEXCHANGE
    Signature = 2    // AT_SIGNATURE
};

class PvkKey
{
  public:
    PvkKey();
    ~PvkKey();

    PvkKey(const PvkKey&) = delete;
    PvkKey& operator=(const PvkKey&) = delete;
    PvkKey(PvkKey&& other) noexcept;
    PvkKey& operator=(PvkKey&& other) noexcept;

    // Load parses the PVK structure but does not decrypt the payload
    void load(const std::string& filePath);

    // Decrypts the loaded payload using the provided password
    void decrypt(const std::string& password);

    // Encrypts the payload using the provided password, optionally using a specific salt
    void encrypt(const std::string& password, const std::vector<uint8_t>& salt = {});

    // Saves the PVK structure to a file
    void save(const std::string& filePath) const;

    // Sets the raw unencrypted PRIVATEKEYBLOB bytes and KeySpec
    void setKeyData(const std::vector<uint8_t>& keyData, PvkKeySpec keyType);

    // Gets the raw unencrypted PRIVATEKEYBLOB bytes
    const std::vector<uint8_t>& getKeyData() const { return m_keyData; }

    // Gets the KeySpec (e.g., AT_KEYEXCHANGE, AT_SIGNATURE)
    PvkKeySpec getKeyType() const { return m_keyType; }

    bool isEncrypted() const { return m_isEncrypted; }

    // Gets the salt bytes (if encrypted)
    const std::vector<uint8_t>& getSalt() const { return m_salt; }

  private:
    PvkKeySpec m_keyType;
    bool m_isEncrypted;
    std::vector<uint8_t> m_salt;
    std::vector<uint8_t> m_payload; // encrypted or unencrypted payload
    std::vector<uint8_t> m_keyData; // decrypted PRIVATEKEYBLOB
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_PVK_KEY_H
