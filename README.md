# Import Scanner

This tool scans all PEs in a directory for the import `CveEventWrite`, a new function that
Writes CVE details to ETW and the Event Log.

Searches both the `Import Address Table` and the `Delay-Load` Table, using the following library: https://github.com/Workshell/pe/

Decided to make this to help look for uses of the new-ish `CveEventWrite` function,
in response to this twitter thread: https://twitter.com/taviso/status/1217824132504535040?s=21

# Build
Build `importscanner.sln`

# Running
Pass in three position arguments:
1. The module to search for, e.g. `kernel32.dll`. Supports wildcarding
2. The function to search for in the module, e.g. `CveEventWrite`. Supports wildcarding
3. The base directory to search, e.g. `C:\Windows\System32`

## Examples
Scan `C:\Windows\System32` for the function `CveEventWrite` in any `api-ms-win-security` DLL.
```bash
importscanner.exe "api-ms-win-security-base.*" "CveEventWrite"
```

Scan for any function `CveEventWrite` imported in any PE on the whole `C:` drive:
```bash
importscanner.exe ".*" "CveEventWrite" C:\
```


## Running in Docker
You can also run it inside a Docker containers, to help with rapid discovery of new uses of this function, e.g.:
```bash
docker run --rm -v <full/path/to/importscanner/bin/x64/Release>:C:\scan mcr.microsoft.com/windows/servercore:1903-KB4528760 C:\scan\importscanner.exe ".*" "CveEventWrite" C:\

# Or Insider containers:
docker run --rm -v <full/path/to/importscanner/bin/x64/Release>:C:\scan mcr.microsoft.com/windows/servercore/insider:10.0.19035.1 C:\scan\importscanner.exe ".*" "CveEventWrite" C:\
```
