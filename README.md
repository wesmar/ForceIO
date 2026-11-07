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
  list    <path>       List visible directory entries (diagnostic)
  locks   <path>       Show which processes lock the file (supports * and ?)
  delete  <path>       Force-delete file or directory (supports * and ?, bypasses WdFilter)
  rename  <src> <dst>  Force-rename/move file or directory
  copy    <src> <dst>  Copy locked file (or snapshot mounted registry hive)
  start                Load driver only
  stop                 Unload driver
  cleanup              Stop driver, remove service, delete temp files
```

### Examples

```cmd
:: Delete a WdFilter-protected file
ForceIO.exe delete "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\Unknown.Log"

:: Move a protected directory
ForceIO.exe rename "C:\ProgramData\Microsoft\Windows Defender" "C:\ProgramData\Microsoft\Windows Defender_"

:: Copy a locked file (or mounted registry hive)
ForceIO.exe copy "C:\Windows\System32\config\SAM" "C:\Temp\SAM.copy"

:: Show which processes lock a file
ForceIO.exe locks "C:\Windows\System32\winevt\Logs\HardwareEvents.evtx"

:: Batch delete locked/protected files using wildcards (* and ?) in a single driver session
ForceIO.exe delete "C:\Windows\System32\winevt\Logs\*.evtx"
ForceIO.exe delete "C:\Windows\System32\winevt\Logs\Hardware?????.evtx"

:: Query locks across files matching wildcards (* and ?)
ForceIO.exe locks "C:\Windows\System32\winevt\Logs\*.evtx"
ForceIO.exe locks "C:\Windows\System32\winevt\Logs\Hardware?????.evtx"

:: Relative paths work from any working directory (e.g. when ForceIO is in System32 / PATH)
cd C:\Windows\System32\winevt\Logs
ForceIO.exe delete *.evtx
ForceIO.exe delete Hardware?????.evtx
ForceIO.exe locks *.evtx
```

---

## How It Works

1. **FDI decompression** — the signed driver binary is LZX-compressed into a CAB archive appended to the application icon. At runtime, FDI decompresses it in memory and writes `forceio.dat` to `%SystemRoot%`.

2. **Atomic driver session** — `CreateServiceW` → `StartServiceW` → `DeviceIoControl` → `ControlService(STOP)` → `DeleteService` → `DeleteFileW`. The service exists in the registry only for the duration of the IOCTL. Zero `Sleep` calls.

3. **Direct IOCTL** — constructs a 0x428-byte `METHOD_BUFFERED` buffer with source path, destination path, operation type, and flags, then calls `DeviceIoControl(0x222124)` for file operations or `0x222128` for lock queries.

4. **Dynamic in-flight mathematical stager** — the driver enforces caller validation by reading the calling process's EXE directly from disk (`ZwCreateFile` → `ZwReadFile`) and requiring two checksums: `XOR == 0x2B` and `ALT == 0x00A88677`. Reaching this modular sum requires a minimum mathematical file size (~158 KB). Rather than carrying ~87 KB of dead-weight static overlay on disk, the distributed `ForceIO.exe` is an ultra-slim ~72 KB binary. At runtime, it dynamically calculates the arithmetic modular correction, synthesizes the padded worker in `%TEMP%\fio_wk_<PID>_<Tick>.exe`, executes the worker with inherited stdio, and unlinks it immediately upon completion. If executed on an already padded binary (e.g., compiled with `-StandalonePatch`), it detects valid checksums and executes directly without spawning.

5. **WOW64 redirection bypass** — disables WOW64 file system redirection on 64-bit systems at startup (`Wow64DisableWow64FsRedirection`), enabling native access to `System32` directories (such as `System32\winevt\Logs\`) without redirection to `SysWOW64`.

6. **CWD path canonicalization** — automatically expands relative paths (`GetFullPathNameW`) so commands work from any working directory, passing fully qualified `\??\C:\...` paths to the kernel driver.

7. **Batch wildcard operations** — when deleting or querying locks using wildcards (`*` and `?`), the driver is loaded once, all matching files are processed within that single atomic session, and the driver is unloaded cleanly at the end.

---

## Technical Details

| Item | Value |
|------|-------|
| Driver | `IObitUnlocker.sys` v1.3.0.20 (x64, WHCP-signed by Microsoft) |
| Device | `\\.\IObitUnlockerDevice` |
| IOCTL | `0x222124` (file ops), `0x222128` (handle query) |
| Buffer | 0x428 bytes: `SourcePath[264 WCHAR]` + `DestPath[264 WCHAR]` + `OpType` + `Flags` |
| Operations | 1=delete, 2=raw rename, 3=move/cut, 4=copy |
| Checksum targets | XOR=`0x2B`, ALT=`0x00A88677` (hardcoded at driver+0x3DC7) |
| Stager mechanism | Dynamic in-flight mathematical padding synthesis (`%TEMP%\fio_wk_*.exe`) |
| Binary size | ~72 KB standalone executable (includes compressed 64-bit kernel driver) |
| Compilation | `/NODEFAULTLIB`, `/ENTRY:Entry`, `/GS-`, `/W4`, `/WX` — pure Win32 API |
| Imports | `kernel32.dll`, `advapi32.dll`, `cabinet.dll` |
| Architecture | PE32 (x86) — IOCTL is bitness-transparent via `METHOD_BUFFERED` |
| Technique | BYOPD — Bring Your Own Overpowered Driver: signed, legitimate primitives, weak caller validation |

### Why not patch the driver instead?

Patching 4 bytes in the driver (two `jne` → `NOP NOP` at `+0x3DCC` and `+0x3DD6`) would disable caller validation entirely. However, this invalidates the WHCP Authenticode signature and the driver will not load under Driver Signature Enforcement (the default on all supported Windows configurations).

While the driver mathematically requires a minimum on-disk file size (~158 KB) to satisfy the alternating sum `ALT == 0x00A88677`, this constraint applies to the *calling image file on disk* when `ZwCreateFile` is executed by ring 0, not to the distributed executable itself. ForceIO decouples this constraint via runtime stager synthesis: the distributed binary remains an ultra-slim ~72 KB, while the ephemeral worker satisfying ring 0 exists on disk only for the millisecond duration of the IOCTL.

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
5. Verifies no CRT dependencies (`kernel32.dll`, `advapi32.dll`, `cabinet.dll` only).
6. Outputs clean, unpadded ~72 KB binary with dynamic in-flight stager (or pass `-StandalonePatch` for pre-padded 158 KB binary).
7. Sets deterministic timestamps.

Output: `bin\ForceIO.exe` (~72 KB)

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
│   ├── Stager.c/.h          Dynamic in-flight mathematical stager & worker spawner
│   ├── DeviceIO.c/.h        IOCTL protocol, buffer construction
│   ├── HiveIO.c/.h          Registry hive copy via RegSaveKeyExW (bypasses kernel hive lock)
│   ├── DriverSession.c/.h   Atomic SCM lifecycle (Begin/End)
│   ├── DriverExtract.c/.h   FDI in-memory decompression
│   ├── Console.c/.h         No-CRT console output
│   ├── PathSafety.h         Path canonicalization and WOW64 bypass
│   ├── GenIconSize.h        Auto-generated icon header size
│   ├── Resource.h           Resource identifiers
│   ├── ForceIO.rc           Icon + RCDATA resource
│   ├── ForceIO.manifest     UAC elevation manifest
│   └── ForceIO.vcxproj      Visual Studio project (Win32 Release)
├── build.ps1                Full build pipeline + checksum patch
└── bin/
    └── ForceIO.exe          Final standalone binary
```

### Driver binary

The driver binary (`IObitUnlocker.sys`) is **not included** in this repository. To build ForceIO, place a legally obtained copy of `IObitUnlocker.sys` v1.3.0.20 as `IcoBuilder\forceio.dat`. The driver is available in the [IObit Unlocker](https://www.iobit.com/en/iobit-unlocker.php) freeware installer.

---

## Requirements

- **OS:** Windows 10/11 x64 (tested on Windows 11 Pro **26H2** build 10.0.26300 and **26H1** build 10.0.28000, fully patched)
- **Privileges:** Administrator (SCM service creation requires elevation)
- **DSE:** Enabled (driver is genuinely WHCP-signed)
- **HVCI:** Compatible (driver loads normally under Hypervisor Code Integrity)

---

## Full Writeup

The complete reverse engineering writeup — including IDA static analysis, CDB live disassembly, 56-function IAT reconstruction, four failed bypass attempts, the mathematical proof of irreducible padding, detailed driver architecture, and a discussion of why **BYOPD** (Bring Your Own Overpowered Driver) is a more precise classification than BYOVD for drivers that expose overpowered primitives without memory-safety exploits — is published at:

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
