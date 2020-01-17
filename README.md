# CveEventWrite Import Scanner

This tool scans all PEs in a directory for the import `CveEventWrite`, a new function that
Writes CVE details to ETW and the Event Log

# Build
Build `importscanner.sln`

# Run - Standalone
## Scan all PEs in `C:\Windows\System32`
```bash
importscanner.exe
```

## Scan all PEs in arbitrary folder
```bash
importscanner.exe <path/to/folder>
```

# Run - Docker
You can also run it inside a Docker containers, to help with rapid discovery of new uses of this function, e.g.:
```bat
docker run --rm -v <full/path/to/importscanner/bin/x64/Release>:C:\scan mcr.microsoft.com/windows/servercore:1903-KB4528760 C:\scan\importscanner.exe
```

or insider builds:
```bat
docker run --rm -v <full/path/to/importscanner/bin/x64/Release>:C:\scan mcr.microsoft.com/windows/servercore/insider:10.0.19035.1 C:\scan\importscanner.exe
```
