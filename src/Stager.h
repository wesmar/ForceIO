#pragma once
#include <windows.h>

#define FORCEIO_TARGET_XOR 0x2B
#define FORCEIO_TARGET_ALT 0x00A88677

// Checks if the current process is already running as a worker,
// or if its on-disk image already matches the required driver checksums.
// If unpadded, creates a temporary patched worker in %TEMP%, executes it,
// waits for it, deletes the temporary file, and sets *pExitCode.
// Returns TRUE if worker was launched and finished (caller should ExitProcess(*pExitCode)).
// Returns FALSE if caller should execute directly.
BOOL Stager_EnsurePadded(DWORD* pExitCode);
