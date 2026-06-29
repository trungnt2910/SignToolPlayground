# ccky Rules

## ccky Components

- The frontend (src/commands):
  + MUST NOT contain any OS-specific or third-party library call.
  + MUST handle invalid parameters messages and error out before passing to the backend.
    - For errors that causes the backend to fail with a generic/unknown error message,
    you should let the backend handle instead.
- The backend (src/crypto):
  + MUST NOT refer to any frontend tool.
  + MUST communicate errors via exceptions.
- The CLI parser:
  + MUST NOT handle command-specific logic.

## ccky Tests

- You MUST NOT hard code any test-specific data or conditions in the application code.
- All new tests MUST follow the Arrange/Act/Assert pattern.
  + Arrange/Act/Assert blocks MUST stay together, with one newline between blocks.
  + If there are mutiple act/assert groups, you MUST split it into two tests instead.
  + The blocks MUST be clear based on only the spacing. DO NOT add comments like `// Arrange`.
  + Command line parameters or other preparation MUST be in the Arrange block.
  + Reloading of output files MUST be in the Act block, not the Assert block.
- Tests must not be guarded by macros. Macro-guarded skips MUST be in the test body instead.
- Tool-level integration tests MUST NOT make backend-specific assumptions.
  + Only skipping commands unsupported by a specific backend is allowed.
- Always check if there is already a helper in CckyTest.h. You MUST use those helpers for
common scenarios, including:
  + Registering temporary system resources (files, certificates, etc.) for cleanup.
  + Loading and comparing test files.
- For readability, split command-line args array into multiple lines, each argument one line.
- Avoid having a clean block. Instead, try to use the resource register functions in `CckyTest.h`.

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
- You MUST NOT detect errors by looking at the exception string.
