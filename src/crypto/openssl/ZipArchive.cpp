#include "crypto/openssl/ZipArchive.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#include <zlib.h>

namespace ccky
{
namespace crypto
{

namespace
{
bool matchMagic(const uint8_t* p, const uint8_t m[4])
{
    return p[0] == m[0] && p[1] == m[1] && p[2] == m[2] && p[3] == m[3];
}
bool matchMagic(const char* p, const uint8_t m[4])
{
    return static_cast<uint8_t>(p[0]) == m[0] && static_cast<uint8_t>(p[1]) == m[1] &&
           static_cast<uint8_t>(p[2]) == m[2] && static_cast<uint8_t>(p[3]) == m[3];
}
} // namespace

void ZipSerializer::writeUint16(uint8_t* buf, uint16_t val)
{
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
}

void ZipSerializer::writeUint32(uint8_t* buf, uint32_t val)
{
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

void ZipSerializer::writeUint64(uint8_t* buf, uint64_t val)
{
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[4] = static_cast<uint8_t>((val >> 32) & 0xFF);
    buf[5] = static_cast<uint8_t>((val >> 40) & 0xFF);
    buf[6] = static_cast<uint8_t>((val >> 48) & 0xFF);
    buf[7] = static_cast<uint8_t>((val >> 56) & 0xFF);
}

void ZipSerializer::writeUint16(std::vector<uint8_t>& buf, uint16_t val)
{
    uint8_t tmp[2];
    writeUint16(tmp, val);
    buf.insert(buf.end(), tmp, tmp + 2);
}

void ZipSerializer::writeUint32(std::vector<uint8_t>& buf, uint32_t val)
{
    uint8_t tmp[4];
    writeUint32(tmp, val);
    buf.insert(buf.end(), tmp, tmp + 4);
}

void ZipSerializer::writeUint64(std::vector<uint8_t>& buf, uint64_t val)
{
    uint8_t tmp[8];
    writeUint64(tmp, val);
    buf.insert(buf.end(), tmp, tmp + 8);
}

void ZipSerializer::serializeCentralDirHeader(
    std::vector<uint8_t>& buf, const ZipEntry& e, const std::string& name, uint64_t offset)
{
    bool hasZip64 = false;
    size_t extraOff = 0;
    std::vector<uint8_t> extraCopy = e.extra;
    while (extraOff + 4 <= extraCopy.size())
    {
        uint16_t tag = static_cast<uint16_t>(extraCopy[extraOff]) |
                       (static_cast<uint16_t>(extraCopy[extraOff + 1]) << 8);
        uint16_t sz = static_cast<uint16_t>(extraCopy[extraOff + 2]) |
                      (static_cast<uint16_t>(extraCopy[extraOff + 3]) << 8);
        if (extraOff + 4 + sz > extraCopy.size())
        {
            break;
        }
        if (tag == ZipConstants::Zip64ExtraFieldTag && sz >= ZipConstants::Zip64ExtraFieldMinSize)
        {
            hasZip64 = true;
            size_t cur = extraOff + 4;
            writeUint64(&extraCopy[cur], e.uncompSize);
            writeUint64(&extraCopy[cur + 8], e.compSize);
            writeUint64(&extraCopy[cur + 16], offset);
            break;
        }
        extraOff += 4 + sz;
    }

    buf.insert(buf.end(), ZipMagic::CentralDirHeader, ZipMagic::CentralDirHeader + 4);
    writeUint16(buf, e.versionMadeBy);
    writeUint16(buf, e.versionNeeded);
    writeUint16(buf, e.gpFlags);
    writeUint16(buf, e.compressionMethod);
    writeUint16(buf, e.modTime);
    writeUint16(buf, e.modDate);
    writeUint32(buf, e.crc32);
    writeUint32(buf, hasZip64 ? ZipConstants::Zip64HeaderMask : static_cast<uint32_t>(e.compSize));
    writeUint32(
        buf, hasZip64 ? ZipConstants::Zip64HeaderMask : static_cast<uint32_t>(e.uncompSize));
    writeUint16(buf, static_cast<uint16_t>(name.size()));
    writeUint16(buf, static_cast<uint16_t>(extraCopy.size()));
    writeUint16(buf, static_cast<uint16_t>(e.comment.size()));
    writeUint16(buf, 0);
    writeUint16(buf, 0);
    writeUint32(buf, 0);
    writeUint32(buf, hasZip64 ? ZipConstants::Zip64HeaderMask : static_cast<uint32_t>(offset));
    buf.insert(buf.end(), name.begin(), name.end());
    if (!extraCopy.empty())
    {
        buf.insert(buf.end(), extraCopy.begin(), extraCopy.end());
    }
    if (!e.comment.empty())
    {
        buf.insert(buf.end(), e.comment.begin(), e.comment.end());
    }
}

void ZipSerializer::serializeLocalFileHeader(
    std::vector<uint8_t>& buf, const ZipEntry& e, const std::string& name)
{
    buf.insert(buf.end(), ZipMagic::LocalFileHeader, ZipMagic::LocalFileHeader + 4);
    writeUint16(buf, e.versionNeeded);
    writeUint16(buf, e.gpFlags);
    writeUint16(buf, e.compressionMethod);
    writeUint16(buf, e.modTime);
    writeUint16(buf, e.modDate);
    writeUint32(buf, e.crc32);
    writeUint32(buf, static_cast<uint32_t>(e.compSize));
    writeUint32(buf, static_cast<uint32_t>(e.uncompSize));
    writeUint16(buf, static_cast<uint16_t>(name.size()));
    writeUint16(buf, 0);
}

void ZipSerializer::serializeEndOfCentralDir(
    std::vector<uint8_t>& buf, uint16_t numEntries, uint64_t cdSize, uint64_t cdOffset)
{
    buf.insert(buf.end(), ZipMagic::EndOfCentralDir, ZipMagic::EndOfCentralDir + 4);
    writeUint16(buf, 0);
    writeUint16(buf, 0);
    writeUint16(buf, numEntries);
    writeUint16(buf, numEntries);
    writeUint32(buf, static_cast<uint32_t>(cdSize));
    writeUint32(buf, static_cast<uint32_t>(cdOffset));
    writeUint16(buf, 0);
}

ZipArchive::ZipArchive(const std::string& filePath) : m_filePath(filePath) { load(filePath); }

bool ZipArchive::hasEntry(const std::string& name) const
{
    return m_entries.find(name) != m_entries.end();
}

const ZipEntry* ZipArchive::getEntry(const std::string& name) const
{
    auto it = m_entries.find(name);
    if (it != m_entries.end())
    {
        return &it->second;
    }
    return nullptr;
}

void ZipArchive::load(const std::string& filePath)
{
    if (!std::filesystem::exists(filePath))
    {
        throw std::runtime_error("File not found: " + filePath);
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open zip file: " + filePath);
    }

    file.seekg(0, std::ios::end);
    uint64_t fileSize = file.tellg();
    if (fileSize < 22)
    {
        throw std::runtime_error("Invalid zip file size");
    }

    uint64_t searchLen = std::min(fileSize, static_cast<uint64_t>(65557));
    std::vector<uint8_t> buf(searchLen);
    file.seekg(fileSize - searchLen, std::ios::beg);
    file.read(reinterpret_cast<char*>(buf.data()), searchLen);
    file.clear();

    uint64_t eocdOffset = 0;
    bool found = false;
    for (int64_t i = static_cast<int64_t>(searchLen) - 22; i >= 0; --i)
    {
        if (matchMagic(&buf[i], ZipMagic::EndOfCentralDir))
        {
            eocdOffset = fileSize - searchLen + i;
            found = true;
            break;
        }
    }

    if (!found)
    {
        throw std::runtime_error("EOCD not found");
    }

    file.seekg(eocdOffset + 10, std::ios::beg);
    uint16_t numEntries = 0;
    uint32_t cdSize = 0;
    uint32_t cdOffset = 0;
    file.read(reinterpret_cast<char*>(&numEntries), 2);
    file.read(reinterpret_cast<char*>(&cdSize), 4);
    file.read(reinterpret_cast<char*>(&cdOffset), 4);

    uint64_t totalEntries = numEntries;
    if (numEntries == 0xFFFF || cdOffset == 0xFFFFFFFF)
    {
        if (eocdOffset >= 20)
        {
            file.seekg(eocdOffset - 20, std::ios::beg);
            char locSig[4];
            if (file.read(locSig, 4) && matchMagic(locSig, ZipMagic::Zip64EocdLocator))
            {
                uint32_t diskNum = 0;
                uint64_t zip64EocdOff = 0;
                file.read(reinterpret_cast<char*>(&diskNum), 4);
                file.read(reinterpret_cast<char*>(&zip64EocdOff), 8);

                file.seekg(zip64EocdOff, std::ios::beg);
                char eocd64Sig[4];
                if (file.read(eocd64Sig, 4) && matchMagic(eocd64Sig, ZipMagic::Zip64EocdRecord))
                {
                    file.seekg(zip64EocdOff + 32, std::ios::beg);
                    uint64_t ne64 = 0;
                    uint64_t cs64 = 0;
                    uint64_t co64 = 0;
                    file.read(reinterpret_cast<char*>(&ne64), 8);
                    file.read(reinterpret_cast<char*>(&cs64), 8);
                    file.read(reinterpret_cast<char*>(&co64), 8);
                    totalEntries = ne64;
                    cdSize = static_cast<uint32_t>(cs64);
                    cdOffset = static_cast<uint32_t>(co64);
                }
            }
        }
    }

    file.seekg(cdOffset, std::ios::beg);
    for (uint64_t i = 0; i < totalEntries; ++i)
    {
        char sig[4];
        if (!file.read(sig, 4) || !matchMagic(sig, ZipMagic::CentralDirHeader))
        {
            break;
        }
        ZipEntry entry;
        file.read(reinterpret_cast<char*>(&entry.versionMadeBy), 2);
        file.read(reinterpret_cast<char*>(&entry.versionNeeded), 2);
        file.read(reinterpret_cast<char*>(&entry.gpFlags), 2);
        file.read(reinterpret_cast<char*>(&entry.compressionMethod), 2);
        file.read(reinterpret_cast<char*>(&entry.modTime), 2);
        file.read(reinterpret_cast<char*>(&entry.modDate), 2);
        file.read(reinterpret_cast<char*>(&entry.crc32), 4);
        file.read(reinterpret_cast<char*>(&entry.compSize), 4);
        file.read(reinterpret_cast<char*>(&entry.uncompSize), 4);

        uint16_t nameLen = 0;
        uint16_t extraLen = 0;
        uint16_t commentLen = 0;
        uint16_t diskStart = 0;
        uint16_t intAttr = 0;
        uint32_t extAttr = 0;
        file.read(reinterpret_cast<char*>(&nameLen), 2);
        file.read(reinterpret_cast<char*>(&extraLen), 2);
        file.read(reinterpret_cast<char*>(&commentLen), 2);
        file.read(reinterpret_cast<char*>(&diskStart), 2);
        file.read(reinterpret_cast<char*>(&intAttr), 2);
        file.read(reinterpret_cast<char*>(&extAttr), 4);
        file.read(reinterpret_cast<char*>(&entry.localHeaderOffset), 4);

        std::vector<char> nameBuf(nameLen);
        file.read(nameBuf.data(), nameLen);
        entry.name = std::string(nameBuf.data(), nameLen);

        entry.extra.resize(extraLen);
        if (extraLen > 0)
        {
            file.read(reinterpret_cast<char*>(entry.extra.data()), extraLen);
            size_t off = 0;
            while (off + 4 <= entry.extra.size())
            {
                uint16_t tag = static_cast<uint16_t>(entry.extra[off]) |
                               (static_cast<uint16_t>(entry.extra[off + 1]) << 8);
                uint16_t sz = static_cast<uint16_t>(entry.extra[off + 2]) |
                              (static_cast<uint16_t>(entry.extra[off + 3]) << 8);
                if (off + 4 + sz > entry.extra.size())
                {
                    break;
                }
                if (tag == ZipConstants::Zip64ExtraFieldTag)
                {
                    size_t cur = off + 4;
                    auto readZip64Field = [&](uint64_t& field)
                    {
                        if (field == ZipConstants::Zip64HeaderMask && cur + 8 <= off + 4 + sz)
                        {
                            uint64_t val = 0;
                            for (int k = 0; k < 8; ++k)
                            {
                                val |= static_cast<uint64_t>(entry.extra[cur + k]) << (8 * k);
                            }
                            field = val;
                            cur += 8;
                        }
                    };
                    readZip64Field(entry.uncompSize);
                    readZip64Field(entry.compSize);
                    readZip64Field(entry.localHeaderOffset);
                }
                off += 4 + sz;
            }
        }
        entry.comment.resize(commentLen);
        if (commentLen > 0)
        {
            file.read(reinterpret_cast<char*>(entry.comment.data()), commentLen);
        }

        m_entryOrder.push_back(entry.name);
        m_entries[entry.name] = entry;
    }

    std::vector<std::pair<uint64_t, std::string>> physOrder;
    for (const auto& pair : m_entries)
    {
        physOrder.push_back({pair.second.localHeaderOffset, pair.first});
    }
    std::sort(physOrder.begin(), physOrder.end());

    for (size_t i = 0; i < physOrder.size(); ++i)
    {
        ZipEntry& entry = m_entries[physOrder[i].second];
        uint64_t start = entry.localHeaderOffset;
        uint64_t end = cdOffset;
        if (i + 1 < physOrder.size())
        {
            end = physOrder[i + 1].first;
        }
        if (end > start)
        {
            entry.rawBytes.resize(end - start);
            file.seekg(start, std::ios::beg);
            file.read(reinterpret_cast<char*>(entry.rawBytes.data()), entry.rawBytes.size());
        }
    }
}

std::vector<uint8_t> ZipArchive::getUncompressedContent(const std::string& name) const
{
    auto it = m_entries.find(name);
    if (it == m_entries.end() || it->second.rawBytes.size() < 30)
    {
        return {};
    }
    const ZipEntry& entry = it->second;
    const uint8_t* p = entry.rawBytes.data();
    if (!matchMagic(p, ZipMagic::LocalFileHeader))
    {
        return {};
    }
    uint16_t nameLen = p[26] | (p[27] << 8);
    uint16_t extraLen = p[28] | (p[29] << 8);
    uint64_t dataOffset = 30 + nameLen + extraLen;
    if (entry.rawBytes.size() < dataOffset + entry.compSize)
    {
        return {};
    }
    const uint8_t* compData = p + dataOffset;

    if (entry.compressionMethod == 0)
    {
        return std::vector<uint8_t>(compData, compData + entry.compSize);
    }
    if (entry.compressionMethod == ZipConstants::DeflateMethod)
    {
        std::vector<uint8_t> uncompData(entry.uncompSize);
        z_stream strm = {};
        strm.next_in = const_cast<Bytef*>(compData);
        strm.avail_in = entry.compSize;
        strm.next_out = uncompData.data();
        strm.avail_out = uncompData.size();
        if (inflateInit2(&strm, -15) != Z_OK)
        {
            return {};
        }
        int res = inflate(&strm, Z_FINISH);
        inflateEnd(&strm);
        if (res != Z_STREAM_END && res != Z_OK)
        {
            return {};
        }
        return uncompData;
    }
    return {};
}

void ZipArchive::setEntryContent(
    const std::string& name, const std::vector<uint8_t>& data, bool compress)
{
    ZipEntry entry;
    auto it = m_entries.find(name);
    if (it != m_entries.end())
    {
        entry = it->second;
    }
    else
    {
        entry.name = name;
        entry.versionMadeBy = ZipConstants::VersionMadeByZip64;
        entry.versionNeeded = ZipConstants::VersionNeededDefault;
        m_entryOrder.push_back(name);
    }

    entry.gpFlags &= ~ZipGeneralPurposeFlags::DataDescriptor;
    entry.uncompSize = data.size();
    entry.crc32 = static_cast<uint32_t>(::crc32(0, data.data(), static_cast<uInt>(data.size())));

    std::vector<uint8_t> compData;
    if (compress && !data.empty())
    {
        entry.compressionMethod = ZipConstants::DeflateMethod;
        uLong bound = compressBound(static_cast<uLong>(data.size()));
        compData.resize(bound);
        z_stream strm = {};
        strm.next_in = const_cast<Bytef*>(data.data());
        strm.avail_in = static_cast<uInt>(data.size());
        strm.next_out = compData.data();
        strm.avail_out = static_cast<uInt>(compData.size());
        deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        deflate(&strm, Z_FINISH);
        deflateEnd(&strm);
        compData.resize(strm.total_out);
        entry.compSize = compData.size();
    }
    else
    {
        entry.compressionMethod = 0;
        compData = data;
        entry.compSize = data.size();
    }

    entry.rawBytes.clear();
    ZipSerializer::serializeLocalFileHeader(entry.rawBytes, entry, name);
    entry.rawBytes.insert(entry.rawBytes.end(), name.begin(), name.end());
    if (!compData.empty())
    {
        entry.rawBytes.insert(entry.rawBytes.end(), compData.begin(), compData.end());
    }

    m_entries[name] = entry;
}

void ZipArchive::removeEntry(const std::string& name)
{
    m_entries.erase(name);
    m_entryOrder.erase(
        std::remove(m_entryOrder.begin(), m_entryOrder.end(), name), m_entryOrder.end());
}

void ZipArchive::save(const std::string& destPath)
{
    std::string tmpPath = destPath + ".tmp";
    std::ofstream out(tmpPath, std::ios::binary);
    if (!out.is_open())
    {
        throw std::runtime_error("Failed to create temp file: " + tmpPath);
    }

    uint64_t currOffset = 0;
    for (const auto& name : m_entryOrder)
    {
        ZipEntry& e = m_entries[name];
        e.localHeaderOffset = currOffset;
        out.write(reinterpret_cast<const char*>(e.rawBytes.data()), e.rawBytes.size());
        currOffset += static_cast<uint32_t>(e.rawBytes.size());
    }

    uint64_t cdStart = currOffset;
    for (const auto& name : m_entryOrder)
    {
        const ZipEntry& e = m_entries[name];
        std::vector<uint8_t> cdBuf;
        ZipSerializer::serializeCentralDirHeader(cdBuf, e, name, e.localHeaderOffset);
        out.write(reinterpret_cast<const char*>(cdBuf.data()), cdBuf.size());
        currOffset += static_cast<uint32_t>(cdBuf.size());
    }

    uint64_t cdSize = currOffset - cdStart;
    uint16_t totalEntries = static_cast<uint16_t>(m_entryOrder.size());
    std::vector<uint8_t> eocd;
    ZipSerializer::serializeEndOfCentralDir(eocd, totalEntries, cdSize, cdStart);
    out.write(reinterpret_cast<const char*>(eocd.data()), eocd.size());
    out.close();

    std::filesystem::rename(tmpPath, destPath);
}

} // namespace crypto
} // namespace ccky
