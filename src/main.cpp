#include <ccky/app/application.h>
#include <ccky/app/backend.h>

#include <iostream>
#include <vector>

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
