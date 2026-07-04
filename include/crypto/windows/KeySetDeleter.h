#ifndef CCKY_KEY_SET_DELETER_H
#define CCKY_KEY_SET_DELETER_H

#include <memory>
#include <string>

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include "crypto/Certificate.h"

namespace ccky
{
namespace crypto
{

class KeySetDeleter
{
  public:
    KeySetDeleter(std::wstring containerName, std::wstring providerName, DWORD providerType);
    explicit KeySetDeleter(const CertificatePtr& cert);
    explicit KeySetDeleter(PCCERT_CONTEXT pCert);
    explicit KeySetDeleter(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv);
    ~KeySetDeleter();

    void dismiss();

  private:
    void initFromCertContext(PCCERT_CONTEXT pCert);
    void initFromHandle(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyOrProv);

    std::wstring m_containerName;
    std::wstring m_providerName;
    DWORD m_providerType;
    bool m_active;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_KEY_SET_DELETER_H
