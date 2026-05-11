# `ccky.exe certmgr`

`ccky.exe certmgr` is a compatibility-focused subset of `certmgr.exe`.

Reference specification: <https://learn.microsoft.com/en-us/dotnet/framework/tools/certmgr-exe-certificate-manager-tool>

## Currently supported invocation

```powershell
ccky.exe certmgr /put /c <source-store> <certificate-file>
```

## Supported behavior

- `/put`
- `/c`
- Reading certificate sources from:
  - signed PE executables
  - `.cer` certificate files
- Exporting the first certificate found in the source to a DER-encoded `.cer` file

## Not yet implemented

Any `certmgr.exe` switch outside the invocation above currently returns an error.
