// DriverExtract.h
// FDI in-memory decompression of the driver payload from icon+CAB resource.
// © WESMAR Marek Wesołowski

#pragma once

#include <windows.h>

// Decompresses forceio.dat from the embedded icon+CAB resource
// and writes it to destFullPath. Returns TRUE on success or if
// the file is already present (locked by running driver).
BOOL DriverExtract_Deploy(const wchar_t* destFullPath);
