#ifndef CCKY_WIN_WRAPPER_H
#define CCKY_WIN_WRAPPER_H

#include <memory>

#include <windows.h>

#include <wincrypt.h>

namespace ccky
{
namespace crypto
{

struct CertContextDeleter
{
    void operator()(PCCERT_CONTEXT p) const
    {
        if (p)
        {
            CertFreeCertificateContext(p);
        }
    }
};
using CertContextPtr = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

struct CrlContextDeleter
{
    void operator()(PCCRL_CONTEXT p) const
    {
        if (p)
        {
            CertFreeCRLContext(p);
        }
    }
};
using CrlContextPtr = std::unique_ptr<const CRL_CONTEXT, CrlContextDeleter>;

struct CtlContextDeleter
{
    void operator()(PCCTL_CONTEXT p) const
    {
        if (p)
        {
            CertFreeCTLContext(p);
        }
    }
};
using CtlContextPtr = std::unique_ptr<const CTL_CONTEXT, CtlContextDeleter>;

struct CertStoreDeleter
{
    void operator()(HCERTSTORE p) const
    {
        if (p)
        {
            CertCloseStore(p, 0);
        }
    }
};
using CertStorePtr = std::unique_ptr<void, CertStoreDeleter>;

struct CryptMsgDeleter
{
    void operator()(HCRYPTMSG p) const
    {
        if (p)
        {
            CryptMsgClose(p);
        }
    }
};
using CryptMsgPtr = std::unique_ptr<void, CryptMsgDeleter>;

struct HandleDeleter
{
    void operator()(HANDLE p) const
    {
        if (p && p != INVALID_HANDLE_VALUE)
        {
            CloseHandle(p);
        }
    }
};
using HandlePtr = std::unique_ptr<void, HandleDeleter>;

struct LocalFreeDeleter
{
    void operator()(void* p) const
    {
        if (p)
        {
            LocalFree(p);
        }
    }
};
template <typename T> using LocalFreePtr = std::unique_ptr<T, LocalFreeDeleter>;

struct CryptProvDeleter
{
    using pointer = HCRYPTPROV;
    void operator()(HCRYPTPROV p) const
    {
        if (p)
        {
            CryptReleaseContext(p, 0);
        }
    }
};
using CryptProvPtr = std::unique_ptr<HCRYPTPROV, CryptProvDeleter>;

struct CryptHashDeleter
{
    using pointer = HCRYPTHASH;
    void operator()(HCRYPTHASH p) const
    {
        if (p)
        {
            CryptDestroyHash(p);
        }
    }
};
using CryptHashPtr = std::unique_ptr<HCRYPTHASH, CryptHashDeleter>;

struct CryptKeyDeleter
{
    using pointer = HCRYPTKEY;
    void operator()(HCRYPTKEY p) const
    {
        if (p)
        {
            CryptDestroyKey(p);
        }
    }
};
using CryptKeyPtr = std::unique_ptr<HCRYPTKEY, CryptKeyDeleter>;

class KeySetDeleter
{
  public:
    KeySetDeleter(std::wstring containerName, std::wstring providerName, DWORD providerType)
        : m_containerName(std::move(containerName)), m_providerName(std::move(providerName)),
          m_providerType(providerType), m_active(true)
    {
    }

    ~KeySetDeleter()
    {
        if (m_active && !m_containerName.empty())
        {
            HCRYPTPROV hDel = 0;
            CryptAcquireContextW(&hDel, m_containerName.c_str(),
                m_providerName.empty() ? nullptr : m_providerName.c_str(), m_providerType,
                CRYPT_DELETEKEYSET);
        }
    }

    void dismiss() { m_active = false; }

  private:
    std::wstring m_containerName;
    std::wstring m_providerName;
    DWORD m_providerType;
    bool m_active;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_WIN_WRAPPER_H
