# Optimized C Scanner

`reverse_scanner.c` is the optimized Windows scanner for detecting the observed
ShadowCube DRM wrapper. It reads only the first 128 bytes of each file, logs
progress while scanning, can write a TXT report, and can move encrypted files to
a destination directory.

The Python scanner remains available as the prototype/reference implementation.

## Build

Run:

```powershell
.\build.bat
```

`build.bat` uses the first supported C compiler found on `PATH`:

- Visual Studio C compiler: `cl`
- GCC: `gcc`
- Clang: `clang`

If no compiler is found, install one of these:

- Visual Studio Build Tools with **Desktop development with C++**
- MSYS2 MinGW-w64 GCC

After a successful build, `reverse_scanner.exe` is created in this directory.
The `.exe` can be copied to another Windows computer and run from PowerShell or
Command Prompt.

## Basic Usage

Scan the sample files:

```powershell
.\reverse_scanner.exe .\samples
```

Scan a drive and write a TXT report:

```powershell
.\reverse_scanner.exe --report .\report.txt C:\
```

Scan a drive, write a report, and move encrypted files:

```powershell
.\reverse_scanner.exe --report .\report.txt --move .\dest C:\
```

Only encrypted files are moved. Clear files and suspect files are not moved.

## Move Behavior

Moved files mirror their absolute source path under the move destination. The
drive letter becomes a normal folder name without `:` because Windows cannot
create a normal directory segment named `C:` or `D:`.

For example:

```text
C:\Users\me\secret.docx
```

with:

```powershell
.\reverse_scanner.exe --move .\dest C:\
```

moves to:

```text
.\dest\C\Users\me\secret.docx
```

That gives you a `C` or `D` folder inside the destination that can be reviewed
or overlaid back onto the original drive layout later.

If the destination file already exists, the scanner appends a numeric suffix,
such as `.1`, before the extension.

The scanner first tries a native Windows move. If Windows reports that the file
is on another device, it falls back to copy-then-delete so the source file is
deleted best-effort. Move success or failure is written to the TXT report.

When `--move` is used, the move destination is automatically excluded from the
scan.

## Logging

Progress is logged every 10000 files by default:

```text
[INFO] 10000 files scanned (2536ms)
```

Change the interval:

```powershell
.\reverse_scanner.exe --log-every 50000 C:\
```

Disable progress logs:

```powershell
.\reverse_scanner.exe --log-every 0 C:\
```

Encrypted files are logged immediately:

```text
[FOUND] ENCRYPTED C:\path\file.docx detected
```

Elapsed scan time is printed only in the final summary:

```text
Elapsed: 1234 ms.
```

## Report

Use `--report <path>` to write a TXT report:

```powershell
.\reverse_scanner.exe --report .\shadowcube-report.txt C:\ D:\
```

By default, the report includes encrypted, suspect, and error entries. Add
`--report-all` to include clear files too.

The report summary includes elapsed scan time in milliseconds.

Move results are included on encrypted entries when `--move` is used:

```text
[ENCRYPTED] C:\path\file.docx
  reason: ShadowCube header magic and protection notice
  move: success
  destination: C:\scanner\dest\C\path\file.docx
```

## Options

```text
--report <path>       Write a TXT report.
--move <path>         Move encrypted files into this directory after detection.
--report-all          Include clear files in the TXT report.
--log-every <count>   Print progress every N files. Use 0 to disable.
--loose               Treat DS3200807 alone as encrypted.
--follow-links        Follow directory symlinks and junctions.
--fail-if-found       Exit with code 2 if encrypted or suspect files are found.
--no-color            Disable colored console output.
--help                Show help.
```

## Exit Codes

- `0`: scan completed without errors
- `1`: one or more files/directories could not be inspected, or a move failed
- `2`: `--fail-if-found` was used and encrypted or suspect files were found
