#ifndef CCKY_WIN32_WRAPPER_H
#define CCKY_WIN32_WRAPPER_H

#include <array>
#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include "crypto/CckyHandle.h"
#include "crypto/windows/KeySetDeleter.h"

namespace ccky
{
namespace crypto
{

struct Win32HandleInvalid
{
    bool operator()(HANDLE h) const noexcept { return !h || h == INVALID_HANDLE_VALUE; }
};

using CertContextPtr = CckyHandle<PCCERT_CONTEXT, CertFreeCertificateContext>;
using CrlContextPtr = CckyHandle<PCCRL_CONTEXT, CertFreeCRLContext>;
using CtlContextPtr = CckyHandle<PCCTL_CONTEXT, CertFreeCTLContext>;
using CertStorePtr = CckyHandle<HCERTSTORE, CertCloseStore, std::array<DWORD, 1>{0}>;
using CryptMsgPtr = CckyHandle<HCRYPTMSG, CryptMsgClose>;
using HandlePtr =
    CckyHandle<HANDLE, CloseHandle, CckyDefault{}, CckyNoCopy{}, Win32HandleInvalid{}>;
template <typename T> using LocalFreePtr = CckyHandle<T*, LocalFree>;
using CryptProvPtr = CckyHandle<HCRYPTPROV, CryptReleaseContext, std::array<DWORD, 1>{0}>;
using CryptHashPtr = CckyHandle<HCRYPTHASH, CryptDestroyHash>;
using CryptKeyPtr = CckyHandle<HCRYPTKEY, CryptDestroyKey>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_WRAPPER_H
