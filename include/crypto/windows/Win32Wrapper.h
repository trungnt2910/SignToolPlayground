#ifndef CCKY_WIN32_WRAPPER_H
#define CCKY_WIN32_WRAPPER_H

#include <array>

#ifndef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#endif
#include <windows.h>

#include <bcrypt.h>
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

using CertContextPtr = CckyHandle<PCCERT_CONTEXT, CertFreeCertificateContext, CckyDefault{},
    CertDuplicateCertificateContext>;
using CrlContextPtr =
    CckyHandle<PCCRL_CONTEXT, CertFreeCRLContext, CckyDefault{}, CertDuplicateCRLContext>;
using CtlContextPtr =
    CckyHandle<PCCTL_CONTEXT, CertFreeCTLContext, CckyDefault{}, CertDuplicateCTLContext>;
using CertStorePtr = CckyHandle<HCERTSTORE, CertCloseStore, std::array<DWORD, 1>{0}>;
using CryptMsgPtr = CckyHandle<HCRYPTMSG, CryptMsgClose>;
using HandlePtr =
    CckyHandle<HANDLE, CloseHandle, CckyDefault{}, CckyNoCopy{}, Win32HandleInvalid{}>;
template <typename T> using LocalFreePtr = CckyHandle<T*, LocalFree>;
using CryptProvPtr = CckyHandle<HCRYPTPROV, CryptReleaseContext, std::array<DWORD, 1>{0}>;
using CryptHashPtr = CckyHandle<HCRYPTHASH, CryptDestroyHash>;
using CryptKeyPtr = CckyHandle<HCRYPTKEY, CryptDestroyKey>;
using BCryptAlgHandlePtr =
    CckyHandle<BCRYPT_ALG_HANDLE, BCryptCloseAlgorithmProvider, std::array<ULONG, 1>{0}>;
using BCryptHashHandlePtr = CckyHandle<BCRYPT_HASH_HANDLE, BCryptDestroyHash>;

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN32_WRAPPER_H
