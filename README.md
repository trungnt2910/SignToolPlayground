# CCKY

`ccky.exe` is a small compatibility-oriented Windows tooling playground that currently implements focused subsets of `signtool.exe` and `certmgr.exe` in modern C++ with CMake.

The supported subcommands are implemented against the published Microsoft command-line specifications for `signtool.exe` and `certmgr.exe`.

## Supported commands

- [`ccky.exe signtool`](src/app/signtool/README.md)
- [`ccky.exe certmgr`](src/app/certmgr/README.md)

## Build requirements

- CMake 3.24+
- A modern C++ compiler
- LLVM MinGW when building for Windows hosts via `CCKY_BUILD_FOR_HOST`

All third-party dependencies are consumed with `FetchContent`:

- [WIL](https://github.com/microsoft/wil)
- [GoogleTest](https://github.com/google/googletest) for tests

## Building

### Native / externally provided compiler

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Host-targeted LLVM MinGW build

`CCKY_BUILD_FOR_HOST=ON` requires `clang` as the detected C compiler and appends the appropriate `-target <triple>` for the host processor:

- `x86_64` / `AMD64` -> `x86_64-w64-mingw32`
- `x86` / `i686` -> `i686-w64-mingw32`
- `ARM64` / `aarch64` -> `aarch64-w64-mingw32`
- `ARM*` -> `armv7-w64-mingw32`

```sh
cmake -S . -B build-host -DCCKY_BUILD_FOR_HOST=ON
cmake --build build-host
ctest --test-dir build-host --output-on-failure
```

## Project layout

- `include/ccky/app`: public interfaces for command dispatch and back-end integration.
- `src/app`: command parsing and subcommand execution.
- `src/backend`: platform-specific crypto and certificate handling.
- `tests`: parser tests plus Windows integration coverage for the required scenarios.
- `testdata`: checked-in example PE and certificate artifacts.

## Checked-in example artifacts

- `testdata/minimal-x64.exe`: a minimal PE32+ executable used by tests.
- `testdata/example.cer`: an example DER-encoded certificate fixture.

## CI

GitHub Actions builds and tests the project on Windows with the latest published LLVM MinGW release.
