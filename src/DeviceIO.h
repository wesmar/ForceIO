// DeviceIO.h
// IOCTL protocol interface for IObitUnlocker.sys.
//
// Reversed from IObitUnlocker.sys v1.3.0.10 (WHCP signed):
//
// IOCTL 0x222124 — File operations (METHOD_BUFFERED):
//   Input:  0x428 bytes
//   +0x000  WCHAR SourcePath[264]
//   +0x210  WCHAR DestPath[264]
//   +0x420  ULONG OperationType  (1=delete, 2=raw rename, 3=move, 4=copy)
//   +0x424  ULONG Flags          (always 3 in practice)
//   Output: ULONG (4 bytes, ignored)
//
// IOCTL 0x222128 — Handle query (METHOD_BUFFERED):
//   Input:  WCHAR Path[264] (528 bytes; DestPath/OpType/Flags ignored)
//   Output: WCHAR string "exe_path,PID|exe_path,PID|..." (pipe after every entry)
//           Output buffer must be >= 64 KB (ERROR_INSUFFICIENT_BUFFER if smaller).
//           Empty string (0 bytes returned) means no process locks the file.
//   Dispatch: driver uses SUB IOCTL, 0x222124 → CMP result, 4 → handler.
//
// © WESMAR Marek Wesołowski

#pragma once

#include <windows.h>

HANDLE DeviceIO_Open(void);
void   DeviceIO_Close(HANDLE hDev);

// Each returns the Win32 error code (0 = success).
DWORD  DeviceIO_Delete(HANDLE hDev, const wchar_t* path);
DWORD  DeviceIO_Rename(HANDLE hDev, const wchar_t* src, const wchar_t* dst);
DWORD  DeviceIO_Copy(HANDLE hDev, const wchar_t* src, const wchar_t* dst);

// IOCTL 0x222128: query which processes lock a file.
// Output is a WCHAR string "exe_path,PID|exe_path,PID|..." (pipe after every entry, including last).
// Returns 0 on success; *outBuf allocated with VirtualAlloc — caller must
// VirtualFree(*outBuf, 0, MEM_RELEASE). *outChars = number of wide chars in output.
// Empty file (not locked) → *outBuf non-NULL, *outChars == 0.
DWORD  DeviceIO_QueryLocks(HANDLE hDev, const wchar_t* path, wchar_t** outBuf, DWORD* outChars);
