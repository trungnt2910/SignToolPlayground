#include <ccky/app/application.h>
#include <ccky/app/backend.h>

#include <cwchar>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
int wmain(const int argc, wchar_t** argv)
{
    std::vector<std::wstring> arguments;
    arguments.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        arguments.emplace_back(argv[i]);
    }

    auto backend = ccky::CreatePlatformBackend();
    return ccky::RunApplication(arguments, *backend, std::wcout, std::wcerr);
}
#else
namespace {

std::wstring WidenArgumentFallback(const char* value)
{
    static bool warned = false;
    if (!warned) {
        std::cerr << "ccky: warning: falling back to byte-wise argument conversion.\n";
        warned = true;
    }

    const std::string fallback(value);
    return std::wstring(fallback.begin(), fallback.end());
}

std::wstring WidenArgument(const char* value)
{
    if (value == nullptr || *value == '\0') {
        return {};
    }

    std::mbstate_t state {};
    const char* measurement_source = value;
    const size_t length = std::mbsrtowcs(nullptr, &measurement_source, 0, &state);
    if (length == static_cast<size_t>(-1)) {
        return WidenArgumentFallback(value);
    }

    std::wstring wide(length, L'\0');
    state = std::mbstate_t {};
    const char* source = value;
    if (std::mbsrtowcs(wide.data(), &source, wide.size(), &state) == static_cast<size_t>(-1)) {
        return WidenArgumentFallback(value);
    }
    return wide;
}

} // namespace

int main(const int argc, char** argv)
{
    std::vector<std::wstring> arguments;
    arguments.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        arguments.push_back(WidenArgument(argv[i]));
    }

    auto backend = ccky::CreatePlatformBackend();
    return ccky::RunApplication(arguments, *backend, std::wcout, std::wcerr);
}
#endif
