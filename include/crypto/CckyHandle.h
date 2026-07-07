#ifndef CCKY_HANDLE_H
#define CCKY_HANDLE_H

#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>

#include "crypto/CckyException.h"

namespace ccky
{
namespace crypto
{

struct CckyNoCopy
{
};

struct CckyDefault
{
};

template <typename T, auto Deleter, auto DeleterArgs = CckyDefault{}, auto Copier = CckyNoCopy{},
    auto IsInvalid = CckyDefault{}>
class CckyHandle
{
  public:
    CckyHandle(T h = T(0)) noexcept : m_handle(h) {}

    ~CckyHandle()
    {
        if (isValid())
        {
            destroy(m_handle);
        }
    }

    CckyHandle(const CckyHandle& other)
        requires(!std::is_same_v<decltype(Copier), CckyNoCopy>)
    {
        m_handle = IsInvalid(other.m_handle) ? T(0) : Copier(other.m_handle);
    }

    CckyHandle& operator=(const CckyHandle& other)
        requires(!std::is_same_v<decltype(Copier), CckyNoCopy>)
    {
        if (this != &other)
        {
            reset();
            m_handle = IsInvalid(other.m_handle) ? T(0) : Copier(other.m_handle);
        }
        return *this;
    }

    CckyHandle(CckyHandle&& other) noexcept : m_handle(std::move(other.m_handle))
    {
        other.m_handle = T(0);
    }

    CckyHandle& operator=(CckyHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_handle = std::move(other.m_handle);
            other.m_handle = T(0);
        }
        return *this;
    }

    bool operator==(const CckyHandle&) const = default;
    bool operator==(std::nullptr_t) const noexcept
    {
        if constexpr (std::is_same_v<decltype(IsInvalid), CckyDefault>)
        {
            return m_handle == T(0);
        }
        else
        {
            return IsInvalid(m_handle);
        }
    }

    T& init()
    {
        if (isValid())
        {
            throw CckyException("Attempted to initialize an already open handle");
        }
        return m_handle;
    }

    T operator->() const noexcept
        requires(std::is_pointer_v<T> && !std::is_void_v<std::remove_pointer_t<T>>)
    {
        return m_handle;
    }

    decltype(auto) operator*() const noexcept
        requires(std::is_pointer_v<T> && !std::is_void_v<std::remove_pointer_t<T>>)
    {
        return *m_handle;
    }

    T get() const noexcept { return m_handle; }
    bool isValid() const noexcept
    {
        if constexpr (std::is_same_v<decltype(IsInvalid), CckyDefault>)
        {
            return m_handle != T(0);
        }
        else
        {
            return !IsInvalid(m_handle);
        }
    }

    T release() noexcept
    {
        T temp = std::move(m_handle);
        m_handle = T(0);
        return temp;
    }

    void reset(T newHandle = T(0)) noexcept
    {
        if (m_handle != newHandle)
        {
            if (isValid())
            {
                destroy(m_handle);
            }
            m_handle = std::move(newHandle);
        }
    }

  private:
    void destroy(T h) noexcept
    {
        if constexpr (std::is_same_v<decltype(DeleterArgs), CckyDefault>)
        {
            Deleter(h);
        }
        else
        {
            std::apply([h](const auto&... args) { Deleter(h, args...); }, DeleterArgs);
        }
    }

    T m_handle;
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_HANDLE_H
