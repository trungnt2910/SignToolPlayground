#include "crypto/Console.h"

#include <iostream>

#include <windows.h>

namespace ccky
{
namespace crypto
{

std::string Console::askPasswordStdin(const std::string& prompt)
{
    std::cout << prompt;
    std::string password;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, password);
    SetConsoleMode(hStdin, mode);
    std::cout << std::endl;
    return password;
}

} // namespace crypto
} // namespace ccky
