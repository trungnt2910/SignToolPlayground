#ifndef CCKY_PVK2PFX_CONVERTER_H
#define CCKY_PVK2PFX_CONVERTER_H

#include <string>

namespace ccky
{
namespace crypto
{

struct Pvk2PfxOptions
{
    std::string pvkFile;
    std::string pvkPassword;
    std::string spcFile;
    std::string pfxFile;
    std::string pfxPassword;
    bool force = false;
};

class Pvk2PfxConverter
{
  public:
    static void convert(const Pvk2PfxOptions& opts);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_PVK2PFX_CONVERTER_H
