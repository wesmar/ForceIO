// HiveIO.h
// Registry hive detection and RegSaveKeyExW-based copy.
//
// Handles mounted hive files that the kernel locks exclusively via the registry
// manager (SAM, SYSTEM, SOFTWARE, SECURITY, DEFAULT, NTUSER.DAT, UsrClass.dat,
// and any other hive visible in the kernel hivelist).  These files cannot be
// copied by the IObitUnlocker IOCTL because the locking is not a minifilter oplock
// but a kernel-level hive mapping — the IOCTL path returns ERROR_SHARING_VIOLATION.
// RegSaveKeyExW bypasses this by going through the registry manager itself.
//
// © WESMAR Marek Wesołowski

#pragma once
#include <windows.h>

// Returns non-zero if `path` points to the physical file of a currently mounted
// registry hive (matched against HKLM\SYSTEM\...\hivelist at runtime).
// On success fills rootKeyOut (HKEY_LOCAL_MACHINE or HKEY_USERS) and subKeyOut
// with the subkey string, e.g. L"SAM" or L"S-1-5-21-...-500".
int   HiveIO_IsHivePath(const wchar_t* path, HKEY* rootKeyOut,
                        wchar_t* subKeyOut, int subMax);

// Export a live hive to destPath via RegSaveKeyExW (REG_LATEST_FORMAT).
// Enables SE_BACKUP_NAME privilege before the call.
// Deletes destPath first (RegSaveKeyExW fails if the file already exists).
// Returns Win32 error code (0 = success).
DWORD HiveIO_Save(HKEY rootKey, const wchar_t* subKey, const wchar_t* destPath);
