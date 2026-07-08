#ifndef CCKY_CRYPTO_STRINGS_H
#define CCKY_CRYPTO_STRINGS_H

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <string_view>

namespace ccky
{
namespace crypto
{

class Strings
{
  public:
    template <typename CharT, typename Traits = std::char_traits<CharT>>
    static inline std::basic_string<CharT, Traits> toLower(
        std::basic_string_view<CharT, Traits> str)
    {
        std::basic_string<CharT, Traits> res(str);
        for (auto& c : res)
        {
            c = Traits::to_char_type(std::tolower(Traits::to_int_type(c)));
        }
        return res;
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>,
        typename Allocator = std::allocator<CharT>>
    static inline std::basic_string<CharT, Traits, Allocator> toLower(
        const std::basic_string<CharT, Traits, Allocator>& str)
    {
        return toLower(std::basic_string_view<CharT, Traits>(str));
    }

    template <typename CharT> static inline std::basic_string<CharT> toLower(const CharT* str)
    {
        return str ? toLower(std::basic_string_view<CharT>(str)) : std::basic_string<CharT>();
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>>
    static inline std::basic_string<CharT, Traits> toUpper(
        std::basic_string_view<CharT, Traits> str)
    {
        std::basic_string<CharT, Traits> res(str);
        for (auto& c : res)
        {
            c = Traits::to_char_type(std::toupper(Traits::to_int_type(c)));
        }
        return res;
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>,
        typename Allocator = std::allocator<CharT>>
    static inline std::basic_string<CharT, Traits, Allocator> toUpper(
        const std::basic_string<CharT, Traits, Allocator>& str)
    {
        return toUpper(std::basic_string_view<CharT, Traits>(str));
    }

    template <typename CharT> static inline std::basic_string<CharT> toUpper(const CharT* str)
    {
        return str ? toUpper(std::basic_string_view<CharT>(str)) : std::basic_string<CharT>();
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>>
    static inline bool equalsCaseInsensitiveImpl(
        std::basic_string_view<CharT, Traits> a, std::basic_string_view<CharT, Traits> b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(Traits::to_int_type(a[i])) != std::tolower(Traits::to_int_type(b[i])))
            {
                return false;
            }
        }
        return true;
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>,
        typename Allocator = std::allocator<CharT>>
    static inline bool equalsCaseInsensitive(const std::basic_string<CharT, Traits, Allocator>& a,
        const std::basic_string<CharT, Traits, Allocator>& b)
    {
        return equalsCaseInsensitiveImpl<CharT, Traits>(a, b);
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>,
        typename Allocator = std::allocator<CharT>>
    static inline bool equalsCaseInsensitive(const std::basic_string<CharT, Traits, Allocator>& a,
        std::type_identity_t<std::basic_string_view<CharT, Traits>> b)
    {
        return equalsCaseInsensitiveImpl<CharT, Traits>(a, b);
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>,
        typename Allocator = std::allocator<CharT>>
    static inline bool equalsCaseInsensitive(
        std::type_identity_t<std::basic_string_view<CharT, Traits>> a,
        const std::basic_string<CharT, Traits, Allocator>& b)
    {
        return equalsCaseInsensitiveImpl<CharT, Traits>(a, b);
    }

    template <typename CharT, typename Traits = std::char_traits<CharT>>
    static inline bool equalsCaseInsensitive(std::basic_string_view<CharT, Traits> a,
        std::type_identity_t<std::basic_string_view<CharT, Traits>> b)
    {
        return equalsCaseInsensitiveImpl<CharT, Traits>(a, b);
    }
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_CRYPTO_STRINGS_H
