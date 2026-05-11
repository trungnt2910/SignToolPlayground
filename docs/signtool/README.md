# `ccky.exe signtool`

`ccky.exe signtool` is a compatibility-focused subset of `signtool.exe`.

## Currently supported invocation

```powershell
ccky.exe signtool sign /v /fd sha256 /n <subject-name> <pe-file>
```

## Supported behavior

- `sign`
- `/v`
- `/fd sha256`
- `/n <subject-name>` against `CurrentUser\My`
- PE file signing through Windows signing APIs

## Not yet implemented

Any `signtool.exe` command or switch outside the invocation above currently returns an error.
