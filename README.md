# ForceIO

**Minifilter-bypass file operations via signed kernel driver — standalone tool for deleting, moving, and copying files protected by WdFilter.sys on Windows 11**

> Uses the WHCP-signed `IObitUnlocker.sys` driver to route file I/O below the Filter Manager,
> bypassing WdFilter.sys and other minifilter protections. No IObit DLL, no IObit EXE, no bloatware.

---

## What It Does

ForceIO loads a signed kernel driver via an atomic SCM session and sends a single `DeviceIoControl` call to perform file operations that user-mode APIs cannot:

```
ForceIO.exe delete "C:\ProgramData\Microsoft\Windows Defender\Scans\DefenderEcsCache.bin64"
[*] DELETE: C:\ProgramData\Microsoft\Windows Defender\Scans\DefenderEcsCache.bin64
[+] Success.
```

`Remove-Item -Force` returns **Access denied** on the same path — WdFilter blocks the I/O request.
ForceIO deletes it because the IOCTL routes below the minifilter stack.

---

## Usage

Run from an **elevated command prompt** (Administrator):

```
ForceIO — minifilter-bypass file operations via signed driver
© WESMAR Marek Wesołowski

Usage: ForceIO <command> <path> [dest]

Commands:
  delete <path>       Force-delete file or directory (bypasses WdFilter)
  rename <src> <dst>  Force-rename/move file or directory
  copy   <src> <dst>  Copy locked file
  start               Load driver only
  stop                Unload driver
  cleanup             Stop driver, remove service, delete temp files
```

### Examples

```cmd
:: Delete a WdFilter-protected file
ForceIO.exe delete "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\Unknown.Log"

:: Move a protected directory
ForceIO.exe rename "C:\ProgramData\Microsoft\Windows Defender" "C:\ProgramData\Microsoft\Windows Defender_"

:: Copy a locked file
ForceIO.exe copy "C:\Windows\System32\config\SAM" "C:\Temp\SAM.copy"
```

---

## How It Works

1. **FDI decompression** — the signed driver binary is LZX-compressed into a CAB archive appended to the application icon. At runtime, FDI decompresses it in memory and writes `forceio.dat` to `%SystemRoot%`.

2. **Atomic driver session** — `CreateServiceW` → `StartServiceW` → `DeviceIoControl` → `ControlService(STOP)` → `DeleteService` → `DeleteFileW`. The service exists in the registry only for the duration of the IOCTL. Zero `Sleep` calls.

3. **Direct IOCTL** — constructs a 0x428-byte `METHOD_BUFFERED` buffer with source path, destination path, operation type, and flags, then calls `DeviceIoControl(0x222124)`.

4. **Checksum bypass** — the driver validates callers by computing two checksums (XOR and alternating add/sub) over the calling process's EXE on disk. The build script appends correction bytes to satisfy both constraints without modifying the driver. The WHCP Authenticode signature remains intact.

---

## Technical Details

| Item | Value |
|------|-------|
| Driver | `IObitUnlocker.sys` v1.3.0.10 (x64, WHCP-signed 2022-08-17) |
| Device | `\\.\IObitUnlockerDevice` |
| IOCTL | `0x222124` (file ops), `0x222128` (handle query) |
| Buffer | 0x428 bytes: `SourcePath[264 WCHAR]` + `DestPath[264 WCHAR]` + `OpType` + `Flags` |
| Operations | 1=delete, 2=raw rename, 3=move/cut, 4=copy |
| Checksum targets | XOR=`0x2B`, ALT=`0x00A88677` (hardcoded at driver+0x3DC7) |
| Compilation | `/NODEFAULTLIB`, `/ENTRY:Entry`, `/GS-` — pure Win32 API |
| Imports | `kernel32.dll`, `advapi32.dll`, `cabinet.dll` |
| Architecture | PE32 (x86) — IOCTL is bitness-transparent via `METHOD_BUFFERED` |

### Why not patch the driver instead?

Patching 4 bytes in the driver (two `jne` → `NOP NOP` at `+0x3DCC` and `+0x3DD6`) would disable caller validation entirely. However, this invalidates the WHCP Authenticode signature and the driver will not load under Driver Signature Enforcement (the default on all supported Windows configurations). The ~87 KB of PE overlay padding is the price of preserving the original signature.

---

## Building from Source

Requires **Visual Studio 2026 Enterprise** (MSVC v145, Windows SDK 10.0):

```powershell
cd C:\Projekty\ForceIO
.\build.ps1
```

The build script:
1. LZX-compresses the driver via `makecab` into a CAB archive.
2. Appends the CAB to the application icon (`IcoBuilder\kvc.ico` → `ICON\kvc.ico`).
3. Generates `src\GenIconSize.h` with the icon header byte count (FDI seek offset).
4. Builds `src\ForceIO.vcxproj` as `Release|Win32` via MSBuild.
5. Computes current checksums, appends correction bytes, verifies match.
6. Sets deterministic timestamps.

Output: `bin\ForceIO.exe`

### Project layout

```
ForceIO/
├── IcoBuilder/
│   ├── kvc.ico              Base application icon
│   └── forceio.dat          Signed driver binary (user-supplied)
├── ICON/
│   └── kvc.ico              Combined icon + LZX-CAB payload (built)
├── src/
│   ├── main.c               Entry point, CLI dispatch
│   ├── DeviceIO.c/.h        IOCTL protocol, buffer construction
│   ├── DriverSession.c/.h   Atomic SCM lifecycle (Begin/End)
│   ├── DriverExtract.c/.h   FDI in-memory decompression
│   ├── Console.c/.h         No-CRT console output
│   ├── GenIconSize.h        Auto-generated icon header size
│   ├── Resource.h           Resource identifiers
│   ├── ForceIO.rc           Icon + RCDATA resource
│   ├── ForceIO.manifest     UAC elevation manifest
│   └── ForceIO.vcxproj      Visual Studio project (Win32 Release)
├── build.ps1                Full build pipeline + checksum patch
└── bin/
    └── ForceIO.exe          Patched binary
```

### Driver binary

The driver binary (`IObitUnlocker.sys`) is **not included** in this repository. To build ForceIO, place a legally obtained copy of `IObitUnlocker.sys` v1.3.0.10 as `IcoBuilder\forceio.dat`. The driver is available in the [IObit Unlocker](https://www.iobit.com/en/iobit-unlocker.php) freeware installer.

---

## Requirements

- **OS:** Windows 10/11 x64
- **Privileges:** Administrator (SCM service creation requires elevation)
- **DSE:** Enabled (driver is genuinely WHCP-signed)
- **HVCI:** Compatible (driver loads normally under Hypervisor Code Integrity)

---

## Full Writeup

The complete reverse engineering writeup — including IDA static analysis, CDB live disassembly, 56-function IAT reconstruction, four failed bypass attempts, the mathematical proof of irreducible padding, and detailed driver architecture — is published at:

**https://kvc.pl/research/forceio-minifilter-bypass**

---

## Disclaimer

This software is provided for **authorized security research and educational purposes only** on systems you own or have explicit written permission to test. The author is not responsible for any damage or misuse. Always comply with applicable laws in your jurisdiction.

---

## License

MIT — see [LICENSE.md](LICENSE.md)

**Author:** Marek Wesołowski (WESMAR)
**Contact:** marek@wesolowski.eu.org
**GitHub:** https://github.com/wesmar/ForceIO
