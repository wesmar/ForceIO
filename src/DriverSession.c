// DriverSession.c
// Atomic driver session lifecycle for ForceIO.
//
// Begin: pre-cleanup → FDI extract to %SystemRoot%\forceio.dat →
//        create SCM service "IObitUnlocker" → start → open device handle.
// End:   close device → stop → delete service → remove driver file.
//
// Service never persists in registry between operations.
//
// © WESMAR Marek Wesołowski

#include "DriverSession.h"
#include "DriverExtract.h"
#include "DeviceIO.h"
#include <winsvc.h>

#pragma comment(lib, "advapi32.lib")

#define SERVICE_NAME L"IObitUnlocker"

static wchar_t g_driverPath[MAX_PATH];

static void wcat(wchar_t* dst, const wchar_t* src, int max) {
    int base = 0;
    while (dst[base]) base++;
    int i = 0;
    while (i < max - base - 1 && src[i]) { dst[base + i] = src[i]; i++; }
    dst[base + i] = 0;
}

static void BuildDriverPath(void) {
    if (g_driverPath[0]) return;
    GetWindowsDirectoryW(g_driverPath, MAX_PATH - 32);
    wcat(g_driverPath, L"\\forceio.dat", MAX_PATH);
}

// ─── Internal SCM operations ───────────────────────────────────────────────

static void SvcStop(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS st;
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static void SvcDelete(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, DELETE);
    if (svc) {
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static BOOL SvcCreateAndStart(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;

    SC_HANDLE svc = NULL;

    for (int attempt = 0; attempt < 3; attempt++) {
        svc = CreateServiceW(scm, SERVICE_NAME, SERVICE_NAME,
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                             L"forceio.dat", NULL, NULL, NULL, NULL, NULL);
        if (svc) break;

        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (svc) {
                ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                     SERVICE_ERROR_IGNORE, L"forceio.dat",
                                     NULL, NULL, NULL, NULL, NULL, SERVICE_NAME);
            }
            break;
        }
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            continue;
        }
        break;
    }

    if (!svc) {
        CloseServiceHandle(scm);
        return FALSE;
    }

    BOOL ok = StartServiceW(svc, 0, NULL);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            ok = TRUE;
        } else if (err == ERROR_SERVICE_DISABLED) {
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                 SERVICE_NO_CHANGE, NULL,
                                 NULL, NULL, NULL, NULL, NULL, NULL);
            ok = StartServiceW(svc, 0, NULL);
            if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                ok = TRUE;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// ─── Public API ────────────────────────────────────────────────────────────

HANDLE DriverSession_Begin(void) {
    BuildDriverPath();

    // Pre-cleanup: remove leftovers from crashed session
    SvcStop();
    SvcDelete();

    if (!DriverExtract_Deploy(g_driverPath))
        return INVALID_HANDLE_VALUE;

    if (!SvcCreateAndStart()) {
        DeleteFileW(g_driverPath);
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hDev = DeviceIO_Open();
    if (hDev == INVALID_HANDLE_VALUE) {
        SvcStop();
        SvcDelete();
        DeleteFileW(g_driverPath);
    }
    return hDev;
}

void DriverSession_End(HANDLE hDev) {
    DeviceIO_Close(hDev);
    SvcStop();
    SvcDelete();
    BuildDriverPath();
    DeleteFileW(g_driverPath);
}

BOOL DriverSession_Start(void) {
    BuildDriverPath();
    SvcStop();
    SvcDelete();
    if (!DriverExtract_Deploy(g_driverPath))
        return FALSE;
    return SvcCreateAndStart();
}

void DriverSession_Stop(void) {
    SvcStop();
}

void DriverSession_Cleanup(void) {
    SvcStop();
    SvcDelete();
    BuildDriverPath();
    DeleteFileW(g_driverPath);
}
