#ifndef CCKY_EXCEPTION_H
#define CCKY_EXCEPTION_H

#include <stdexcept>
#include <string>

namespace ccky
{
namespace crypto
{

class CckyException : public std::runtime_error
{
  public:
    explicit CckyException(const std::string& what_arg, bool printHelp = false)
        : std::runtime_error(what_arg), m_shouldPrintHelp(printHelp)
    {
    }
    bool shouldPrintHelp() const { return m_shouldPrintHelp; }

  private:
    bool m_shouldPrintHelp;
};

class CckyCryptoException : public CckyException
{
  public:
    explicit CckyCryptoException(const std::string& what_arg, bool printHelp = false)
        : CckyException(what_arg, printHelp)
    {
    }
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_EXCEPTION_H
