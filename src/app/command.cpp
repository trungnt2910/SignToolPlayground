#include <ccky/app/command.h>

#include <algorithm>
#include <cwctype>

namespace ccky {

ArgumentCursor::ArgumentCursor(const std::vector<std::wstring>& arguments) : arguments_(arguments), index_(1) {}

bool ArgumentCursor::HasMore() const
{
    return index_ < arguments_.size();
}

const std::wstring& ArgumentCursor::Peek() const
{
    return arguments_.at(index_);
}

std::wstring ArgumentCursor::Consume()
{
    return arguments_.at(index_++);
}

bool EqualsInsensitive(const std::wstring_view left, const std::wstring_view right)
{
    return std::equal(
        left.begin(),
        left.end(),
        right.begin(),
        right.end(),
        [](const wchar_t lhs, const wchar_t rhs) {
            return std::towlower(lhs) == std::towlower(rhs);
        });
}

bool IsSwitch(const std::wstring_view token)
{
    return !token.empty() && (token.front() == L'/' || token.front() == L'-');
}

} // namespace ccky
