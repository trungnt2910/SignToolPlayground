#pragma once

#include <cstddef>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace ccky {

class ICryptoBackend;

class ArgumentCursor {
public:
    explicit ArgumentCursor(const std::vector<std::wstring>& arguments);

    [[nodiscard]] bool HasMore() const;
    [[nodiscard]] const std::wstring& Peek() const;
    std::wstring Consume();

private:
    const std::vector<std::wstring>& arguments_;
    size_t index_;
};

[[nodiscard]] bool EqualsInsensitive(std::wstring_view left, std::wstring_view right);
[[nodiscard]] bool IsSwitch(std::wstring_view token);

class Command {
public:
    virtual ~Command() = default;

    [[nodiscard]] virtual std::wstring_view Name() const = 0;
    virtual int Run(ArgumentCursor& cursor, ICryptoBackend& backend, std::wostream& output, std::wostream& error) const = 0;
};

} // namespace ccky
