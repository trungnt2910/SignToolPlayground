# SignToolPlayground

[![Discord Invite][2]][1]

A playground for Project Reality's new open-source signing and certificate utilities.

## Overview

This tool (codename `ccky`) is designed to be the `busybox` for certificate utilities.

It aims to be a cross-platform, drop-in replacement for signing-related components in the
[.NET Framework tools](https://learn.microsoft.com/en-us/dotnet/framework/tools/), which are only
available on Windows machines with the Windows SDK installed.

## Components

This project contains open-source re-implementations of:
- `signtool.exe`
- `certmgr.exe`

`ccky` supports two backends:
- A Windows-specific, fully-featured, and compatible Win32 API backend.
- A cross-platform OpenSSL backend.

## Community

This repo is a part of [Project Reality][1].

Need help using this project? Join me on [Discord][1], and let's find a solution together.

<!-- Replace with Discord invite for project channel. -->
[1]: https://reality.trungnt2910.com/discord
[2]: https://img.shields.io/discord/1185622479436251227?logo=discord&logoColor=white&label=Discord&labelColor=%235865F2
