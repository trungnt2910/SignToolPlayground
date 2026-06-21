#ifndef CCKY_ZIP_ARCHIVE_H
#define CCKY_ZIP_ARCHIVE_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ccky
{
namespace crypto
{

namespace ZipMagic
{
constexpr uint8_t CentralDirHeader[4] = {'P', 'K', 0x01, 0x02};
constexpr uint8_t LocalFileHeader[4] = {'P', 'K', 0x03, 0x04};
constexpr uint8_t EndOfCentralDir[4] = {'P', 'K', 0x05, 0x06};
constexpr uint8_t Zip64EocdRecord[4] = {'P', 'K', 0x06, 0x06};
constexpr uint8_t Zip64EocdLocator[4] = {'P', 'K', 0x06, 0x07};
} // namespace ZipMagic

enum ZipGeneralPurposeFlags : uint16_t
{
    DataDescriptor = 0x0008,
    Utf8Encoding = 0x0800
};

namespace ZipConstants
{
constexpr uint16_t Zip64ExtraFieldTag = 0x0001;
constexpr uint16_t Zip64ExtraFieldMinSize = 24;
constexpr uint32_t Zip64HeaderMask = 0xFFFFFFFF;
constexpr uint16_t DeflateMethod = 8;
constexpr uint16_t VersionMadeByZip64 = 45;
constexpr uint16_t VersionNeededDefault = 20;
} // namespace ZipConstants

struct ZipEntry
{
    std::string name;
    uint16_t versionMadeBy = 45;
    uint16_t versionNeeded = 20;
    uint16_t gpFlags = 0;
    uint16_t compressionMethod = 0;
    uint16_t modTime = 0;
    uint16_t modDate = 0;
    uint32_t crc32 = 0;
    uint64_t compSize = 0;
    uint64_t uncompSize = 0;
    uint64_t localHeaderOffset = 0;
    std::vector<uint8_t> extra;
    std::vector<uint8_t> comment;
    std::vector<uint8_t> rawBytes;
};

class ZipSerializer
{
  public:
    static void writeUint16(std::vector<uint8_t>& buf, uint16_t val);
    static void writeUint32(std::vector<uint8_t>& buf, uint32_t val);
    static void writeUint64(std::vector<uint8_t>& buf, uint64_t val);

    static void writeUint16(uint8_t* buf, uint16_t val);
    static void writeUint32(uint8_t* buf, uint32_t val);
    static void writeUint64(uint8_t* buf, uint64_t val);
    static void serializeCentralDirHeader(
        std::vector<uint8_t>& buf, const ZipEntry& e, const std::string& name, uint64_t offset);
    static void serializeLocalFileHeader(
        std::vector<uint8_t>& buf, const ZipEntry& e, const std::string& name);
    static void serializeEndOfCentralDir(
        std::vector<uint8_t>& buf, uint16_t numEntries, uint64_t cdSize, uint64_t cdOffset);
};

class ZipArchive
{
  public:
    explicit ZipArchive(const std::string& filePath);

    bool hasEntry(const std::string& name) const;
    std::vector<uint8_t> getUncompressedContent(const std::string& name) const;
    void setEntryContent(
        const std::string& name, const std::vector<uint8_t>& data, bool compress = false);
    void removeEntry(const std::string& name);
    void save(const std::string& destPath);

    const std::vector<std::string>& getEntryOrder() const { return m_entryOrder; }
    const ZipEntry* getEntry(const std::string& name) const;

  private:
    void load(const std::string& filePath);

    std::string m_filePath;
    std::vector<std::string> m_entryOrder;
    std::map<std::string, ZipEntry> m_entries;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_ZIP_ARCHIVE_H
