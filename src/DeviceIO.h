// DeviceIO.h
// IOCTL protocol interface for IObitUnlocker.sys.
//
// Reversed from IObitUnlocker.sys v1.3.0.10 (WHCP signed):
//   Buffer: 0x428 bytes, METHOD_BUFFERED
//   +0x000  WCHAR SourcePath[264]
//   +0x210  WCHAR DestPath[264]
//   +0x420  ULONG OperationType
//   +0x424  ULONG Flags
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
