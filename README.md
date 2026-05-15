# Reverse Scanner

This scanner detects the observed ShadowCube DRM wrapper from the sample files in
`samples/`. It does not decrypt files and it does not inspect file contents past
the header bytes needed for classification.

## Observed Pattern

The encrypted samples all start with this ASCII marker:

```text
DS3200807This document is protected by ShadowCube Tech. & Policies.
```

The decrypted samples keep their normal file signatures, for example `PK` for
Office documents, `%PDF` for PDFs, and normal text for `.txt`.

The encrypted files also appear to add a wrapper header of about 1024 bytes plus
possible block padding. For detection, the scanner uses the header marker rather
than the size delta, because size-based detection would be fragile.

## Usage

Scan the included samples:

```powershell
python .\reverse_scanner.py .\samples
```

Write a CSV report:

```powershell
python .\reverse_scanner.py C:\ D:\ --csv .\shadowcube-report.csv
```

Preview moving encrypted files to a staging folder:

```powershell
python .\reverse_scanner.py C:\ D:\ --move-to D:\shadowcube-staging --dry-run
```

Actually move encrypted files after reviewing the dry run:

```powershell
python .\reverse_scanner.py C:\ D:\ --move-to D:\shadowcube-staging --csv .\moved-files.csv
```

By default, symlinks and junctions are not followed. Use `--follow-links` only if
you need it and understand the directory topology.

When `--move-to` is used, that destination is automatically excluded from the
scan so an existing staging directory is not processed again.

## Detection Notes

Default detection requires both:

- file starts with `DS3200807`
- first 128 bytes contain `This document is protected by ShadowCube Tech. & Policies.`

If another version keeps the magic but changes the notice text, use `--loose` to
treat `DS3200807` alone as encrypted. Files matching only the magic are reported
as `SUSPECT` without `--loose`.
