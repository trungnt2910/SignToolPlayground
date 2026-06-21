#ifndef CCKY_FILE_TYPE_DETECTOR_H
#define CCKY_FILE_TYPE_DETECTOR_H

#include <string>

#include "crypto/ICertStore.h"

namespace ccky
{
namespace crypto
{

class FileTypeDetector
{
  public:
    static StoreType detectFileType(const std::string& filePath);

  private:
    static StoreType detectCertType(const std::string& filePath);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_FILE_TYPE_DETECTOR_H
