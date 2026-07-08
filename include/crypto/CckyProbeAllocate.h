#ifndef CCKY_PROBE_ALLOCATE_H
#define CCKY_PROBE_ALLOCATE_H

#include <algorithm>
#include <cstddef>
#include <type_traits>
#include <utility>

namespace ccky
{
namespace crypto
{

template <auto SuccessValue> struct CckyProbeReturn
{
    template <typename Ret> bool operator()(Ret ret) const noexcept
    {
        return ret == static_cast<Ret>(SuccessValue);
    }
};

struct CckyProbeReturnPositive
{
    template <typename Ret> bool operator()(Ret ret) const noexcept { return ret > 0; }
};

struct CckyProbeBytes
{
};

struct CckyProbeSize
{
};

template <typename T> struct CckyProbeBytesRef
{
    T size = 0;

    operator T*() noexcept { return &size; }
    operator const T*() const noexcept { return &size; }
    operator T&() noexcept { return size; }
};

template <typename T> struct CckyProbeSizeRef
{
    T size = 0;

    operator T*() noexcept { return &size; }
    operator const T*() const noexcept { return &size; }
    operator T&() noexcept { return size; }
};

template <typename Container> struct CckyProbeBuffer
{
    using container_type = Container;
    Container& container;

    explicit CckyProbeBuffer(Container& c) noexcept : container(c) {}
};

template <typename Container> CckyProbeBuffer(Container&) -> CckyProbeBuffer<Container>;

template <typename Container> struct CckyProbeString
{
    using container_type = Container;
    Container& container;

    explicit CckyProbeString(Container& c) noexcept : container(c) {}
};

template <typename Container> CckyProbeString(Container&) -> CckyProbeString<Container>;

namespace detail
{

template <bool IsProbe> struct ResolvedProbeSize
{
    size_t size;

    template <typename Int>
        requires std::is_integral_v<Int>
    operator Int() const noexcept
    {
        return static_cast<Int>(IsProbe ? 0 : size);
    }
};

template <typename Container, bool IsProbe> struct ResolvedProbeBuffer
{
    Container& container;

    template <typename Ptr>
        requires std::is_pointer_v<Ptr>
    operator Ptr() const noexcept
    {
        if constexpr (IsProbe)
        {
            return nullptr;
        }
        else
        {
            return reinterpret_cast<Ptr>(container.data());
        }
    }
};

template <typename T> struct IsProbeBytesRef : std::false_type
{
};

template <typename T> struct IsProbeBytesRef<CckyProbeBytesRef<T>> : std::true_type
{
};

template <typename T> struct IsProbeSizeRef : std::false_type
{
};

template <typename T> struct IsProbeSizeRef<CckyProbeSizeRef<T>> : std::true_type
{
};

template <typename T> struct IsProbeBuffer : std::false_type
{
};

template <typename Container> struct IsProbeBuffer<CckyProbeBuffer<Container>> : std::true_type
{
};

template <typename T> struct IsProbeString : std::false_type
{
};

template <typename Container> struct IsProbeString<CckyProbeString<Container>> : std::true_type
{
};

template <typename T> struct IsProbeBytes : std::is_same<std::remove_cvref_t<T>, CckyProbeBytes>
{
};

template <typename T> struct IsProbeSize : std::is_same<std::remove_cvref_t<T>, CckyProbeSize>
{
};

template <bool IsProbe, typename Arg> decltype(auto) resolveArg(Arg&& arg, size_t current_size)
{
    using CleanArg = std::remove_cvref_t<Arg>;
    if constexpr (IsProbeBytes<CleanArg>::value || IsProbeSize<CleanArg>::value)
    {
        return ResolvedProbeSize<IsProbe>{current_size};
    }
    else if constexpr (IsProbeBuffer<CleanArg>::value || IsProbeString<CleanArg>::value)
    {
        return ResolvedProbeBuffer<typename CleanArg::container_type, IsProbe>{arg.container};
    }
    else
    {
        return std::forward<Arg>(arg);
    }
}

template <typename... Args> size_t getProbedSize(auto ret, const Args&... args)
{
    size_t found_size = 0;
    bool found_ref = false;
    auto check = [&](const auto& arg)
    {
        using CleanArg = std::remove_cvref_t<decltype(arg)>;
        if constexpr (IsProbeBytesRef<CleanArg>::value || IsProbeSizeRef<CleanArg>::value)
        {
            found_size = static_cast<size_t>(arg.size);
            found_ref = true;
        }
    };
    (check(args), ...);
    if (found_ref)
    {
        return found_size;
    }
    return static_cast<size_t>(ret);
}

template <bool IsBytes, typename... Args> void resizeBuffer(size_t target_size, Args&... args)
{
    auto tryResize = [&](auto& arg)
    {
        using CleanArg = std::remove_cvref_t<decltype(arg)>;
        if constexpr (IsProbeBuffer<CleanArg>::value || IsProbeString<CleanArg>::value)
        {
            using ValueType = typename CleanArg::container_type::value_type;
            size_t count = target_size;
            if constexpr (IsBytes)
            {
                count = (target_size + sizeof(ValueType) - 1) / sizeof(ValueType);
            }
            arg.container.resize(count);
        }
    };
    (tryResize(args), ...);
}

template <typename... Args> void resizeStringToNullTerminator(Args&... args)
{
    auto tryResize = [](auto& arg)
    {
        using CleanArg = std::remove_cvref_t<decltype(arg)>;
        if constexpr (IsProbeString<CleanArg>::value)
        {
            auto& container = arg.container;
            using ValueType = typename CleanArg::container_type::value_type;
            auto it = std::find(container.begin(), container.end(), ValueType(0));
            size_t new_size = std::distance(container.begin(), it);
            container.resize(new_size);
        }
    };
    (tryResize(args), ...);
}

} // namespace detail

template <auto UnderlyingFunction, auto ProbeSuccess = CckyProbeReturn<1>{}, typename... Args>
decltype(auto) CckyProbeAllocate(Args&&... args)
{
    constexpr int buffer_count =
        (... + static_cast<int>(detail::IsProbeBuffer<std::remove_cvref_t<Args>>::value));
    static_assert(
        buffer_count <= 1, "CckyProbeAllocate allows at most one CckyProbeBuffer parameter");

    constexpr int string_count =
        (... + static_cast<int>(detail::IsProbeString<std::remove_cvref_t<Args>>::value));
    static_assert(
        string_count <= 1, "CckyProbeAllocate allows at most one CckyProbeString parameter");

    static_assert(!(buffer_count > 0 && string_count > 0),
        "CckyProbeAllocate cannot mix CckyProbeBuffer and CckyProbeString parameters");

    constexpr int bytes_ref_count =
        (... + static_cast<int>(detail::IsProbeBytesRef<std::remove_cvref_t<Args>>::value));
    static_assert(
        bytes_ref_count <= 1, "CckyProbeAllocate allows at most one CckyProbeBytesRef parameter");

    constexpr int size_ref_count =
        (... + static_cast<int>(detail::IsProbeSizeRef<std::remove_cvref_t<Args>>::value));
    static_assert(
        size_ref_count <= 1, "CckyProbeAllocate allows at most one CckyProbeSizeRef parameter");

    constexpr int bytes_tag_count =
        (... + static_cast<int>(detail::IsProbeBytes<std::remove_cvref_t<Args>>::value));
    static_assert(
        bytes_tag_count <= 1, "CckyProbeAllocate allows at most one CckyProbeBytes parameter");

    constexpr int size_tag_count =
        (... + static_cast<int>(detail::IsProbeSize<std::remove_cvref_t<Args>>::value));
    static_assert(
        size_tag_count <= 1, "CckyProbeAllocate allows at most one CckyProbeSize parameter");

    constexpr bool has_bytes = (bytes_tag_count + bytes_ref_count) > 0;
    constexpr bool has_elements = (size_tag_count + size_ref_count) > 0;
    static_assert(!(has_bytes && has_elements),
        "CckyProbeAllocate cannot mix CckyProbeBytes (bytes) and "
        "CckyProbeSize (elements) in the same call");

    constexpr bool has_string = string_count > 0;

    size_t current_size = 0;

    while (true)
    {
        auto ret =
            UnderlyingFunction(detail::resolveArg</* IsProbe = */ true>(args, current_size)...);
        if (!ProbeSuccess(ret))
        {
            return ret;
        }

        size_t probed_size = detail::getProbedSize(ret, args...);
        if (probed_size == 0)
        {
            detail::resizeBuffer</* IsBytes = */ has_bytes>(0, args...);
            return ret;
        }

        size_t allocated_size = probed_size;
        if constexpr (has_string)
        {
            allocated_size = probed_size + 1;
        }

        detail::resizeBuffer</* IsBytes = */ has_bytes>(allocated_size, args...);
        current_size = allocated_size;

        auto fetch_ret =
            UnderlyingFunction(detail::resolveArg</* IsProbe = */ false>(args, current_size)...);
        if (!ProbeSuccess(fetch_ret))
        {
            detail::resizeBuffer</* IsBytes = */ has_bytes>(0, args...);
            return fetch_ret;
        }

        size_t fetch_probed_size = detail::getProbedSize(fetch_ret, args...);
        size_t limit_size = current_size;
        if constexpr (has_string)
        {
            limit_size = current_size - 1;
        }

        if (fetch_probed_size <= limit_size)
        {
            if constexpr (has_string)
            {
                detail::resizeStringToNullTerminator(args...);
            }
            else if (fetch_probed_size < current_size)
            {
                detail::resizeBuffer</* IsBytes = */ has_bytes>(fetch_probed_size, args...);
            }
            return fetch_ret;
        }
    }
}

} // namespace crypto
} // namespace ccky

#endif // CCKY_PROBE_ALLOCATE_H
