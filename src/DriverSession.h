// DriverSession.h
// Atomic driver session lifecycle for ForceIO.
//
// Normal file operations use Begin/End — the driver service exists in SCM
// only for the duration of the operation, never persists in registry.
//
// © WESMAR Marek Wesołowski

#pragma once

#include <windows.h>

// Atomic session: extract → create service → start → open device.
// Returns device handle for DeviceIO operations.
// Caller MUST call DriverSession_End when done.
HANDLE DriverSession_Begin(void);

// Close device → stop service → delete service → remove driver file.
void DriverSession_End(HANDLE hDev);

// Manual CLI commands (debugging):
BOOL DriverSession_Start(void);
void DriverSession_Stop(void);
void DriverSession_Cleanup(void);
