# ccky Rules

## ccky Components

- The frontend (src/commands):
  + MUST NOT contain any OS-specific or third-party library call.
  + MUST handle all invalid parameters and error out before passing to the backend.
- The backend (src/crypto):
  + MUST NOT refer to any frontend tool.
  + MUST communicate errors via exceptions.
- The CLI parser:
  + MUST NOT handle command-specific logic.

## ccky Tests

- You MUST NOT hard code any test-specific data or conditions in the application code.

## ccky Structure

- Headers MUST be in include/, source file MUST be in src/, test MUST be in tests/

## ccky Formatting

- Even when not enforced by clang-format, the maximum column size is 100.
- Braces MUST be in their own line.
- One-line blocks under if/while/for MUST still have braces.
- Long initialization lists (e.g. long command arrays, structs with many members) MUST have each
element on a separate line.
- You MUST NOT attempt to disable formatting using clang-format off comments.

## ccky Safety

- Handles and other closable resources from Windows or OpenSSL MUST be wrapped with RAII.

## ccky Verification

- You MUST ensure that both Windows and Linux builds are successful.
- You MUST run through every file with clang-format.
- You MUST ensure all tests are passing on your native platform
- After working, you MUST ensure all temporary files that are not ignored by Git are deleted.

## ccky Anti-Anti-Patterns

- You MUST not use std::ifstream just to check if a file exists. Instead, use std::filesystem.
- You MUST NOT abuse std::fstream just to copy files. Instead, use std::filesystem.
- If there is a similar API that takes a file path, you must prefer using that API to reading the
entire file contents to memory and passing the buffer.
- You MUST use std::filesystem::path APIs to get the file extension instead of getting the last 4
characters.
- You MUST NOT have empty catch blocks. If they are necessary, you MUST add a comment explaining
why.
- You MUST NOT use std::system or any other function that invokes shell commands.
- For filesystem management, you MUST use std::filesystem functions instead of invoking UNIX tools.
- You MUST NOT use `SetLastError` just for the purpose of setting the error for `Win32Check`.
Instead, throw the exception directly. A similar rule applies to the OpenSSL backend.
- You must properly convert std::string to std::wstring and vice-versa using WinHelper helpers. You
MUST NOT do a byte-wise widening or narrowing loop.
