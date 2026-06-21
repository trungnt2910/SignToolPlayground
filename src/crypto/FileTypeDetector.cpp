#include "crypto/FileTypeDetector.h"

#include <fstream>

namespace ccky
{
namespace crypto
{

StoreType FileTypeDetector::detectFileType(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (file.is_open())
    {
        char magic[2];
        if (file.read(magic, 2))
        {
            if (magic[0] == 'P' && magic[1] == 'K')
            {
                return StoreType::AppxFile;
            }
            if (magic[0] == 'M' && magic[1] == 'Z')
            {
                file.seekg(0x3C, std::ios::beg);
                uint32_t peOffset = 0;
                if (file.read(reinterpret_cast<char*>(&peOffset), 4))
                {
                    file.seekg(peOffset, std::ios::beg);
                    char pe[4];
                    if (file.read(pe, 4) && pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' &&
                        pe[3] == '\0')
                    {
                        return StoreType::PeFile;
                    }
                }
            }
        }
    }

    return detectCertType(filePath);
}

} // namespace crypto
} // namespace ccky
