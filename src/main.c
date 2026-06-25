// main.c
// ForceIO — minifilter-bypass file operations via signed IObitUnlocker.sys driver.
//
// Standalone BYOVD tool. No CRT, no IObit DLL/EXE dependency.
// The driver binary is embedded as a PE resource and extracted at runtime.
//
// © WESMAR Marek Wesołowski

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "Console.h"
#include "DriverSession.h"
#include "DeviceIO.h"
#include "HiveIO.h"

int _fltused = 0;

static int wlen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) p++;
    return (int)(p - s);
}

static void wcat(wchar_t* dst, const wchar_t* src, int max) {
    int base = wlen(dst);
    int i = 0;
    while (base + i < max - 1 && src[i]) { dst[base + i] = src[i]; i++; }
    dst[base + i] = 0;
}

static void wcat_ch(wchar_t* dst, wchar_t ch, int max) {
    int base = wlen(dst);
    if (base < max - 1) { dst[base] = ch; dst[base + 1] = 0; }
}

static int weq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static int is_abs_path_start(const wchar_t* s) {
    if (!s) return 0;
    if (s[0] == L'\\' && s[1] == L'\\') return 1;
    if (((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) && s[1] == L':')
        return 1;
    return 0;
}

static void PrintUsage(void) {
    Con_Print(L"ForceIO - minifilter-bypass file operations via signed driver\r\n");
    Con_Print(L"WESMAR - Marek Wesolowski https://kvc.pl\r\n\r\n");
    Con_Print(L"Usage: ForceIO <command> <path> [dest]\r\n\r\n");
    Con_Print(L"Commands:\r\n");
    Con_Print(L"  list    <path>       List visible directory entries (diagnostic)\r\n");
    Con_Print(L"  delete  <path>       Force-delete file (bypasses WdFilter)\r\n");
    Con_Print(L"  rename  <src> <dst>  Force-rename/move file\r\n");
    Con_Print(L"  copy    <src> <dst>  Copy locked file\r\n");
    Con_Print(L"  start                Load driver only\r\n");
    Con_Print(L"  stop                 Stop driver\r\n");
    Con_Print(L"  cleanup              Stop driver, remove service, delete temp files\r\n");
}

#define MAX_ARGS 16
static wchar_t g_cmdline[4096];
static wchar_t* g_argv[MAX_ARGS];

static int ParseCommandLine(void) {
    const wchar_t* raw = GetCommandLineW();
    int i = 0;
    while (raw[i] && i < 4095) { g_cmdline[i] = raw[i]; i++; }
    g_cmdline[i] = 0;

    int argc = 0;
    wchar_t* p = g_cmdline;

    while (*p && argc < MAX_ARGS) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;

        if (*p == L'"') {
            p++;
            g_argv[argc++] = p;
            while (*p && *p != L'"') p++;
            if (*p) *p++ = 0;
        } else {
            g_argv[argc++] = p;
            while (*p && *p != L' ' && *p != L'\t') p++;
            if (*p) *p++ = 0;
        }
    }
    return argc;
}

static void ListVisibleEntries(const wchar_t* dir) {
    wchar_t pattern[MAX_PATH * 2];
    pattern[0] = 0;
    wcat(pattern, dir, MAX_PATH * 2);
    int len = wlen(pattern);
    if (len > 0 && len < (MAX_PATH * 2) - 2 && pattern[len - 1] != L'\\') {
        pattern[len] = L'\\';
        pattern[len + 1] = 0;
    }
    wcat(pattern, L"*", MAX_PATH * 2);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Con_Error(L"[-] List failed, error=");
        Con_Dec(err);
        Con_Error(L" (");
        Con_Hex32(err);
        Con_Error(L")\r\n");
        ExitProcess(err);
    }

    DWORD count = 0;
    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
            continue;

        count++;
        Con_Print((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"[D] " : L"[F] ");
        Con_Print(fd.cFileName);
        Con_Print(L" attr=");
        Con_Hex32(fd.dwFileAttributes);
        Con_Print(L"\r\n");
    } while (FindNextFileW(hFind, &fd));

    DWORD last = GetLastError();
    FindClose(hFind);
    if (last != ERROR_NO_MORE_FILES) {
        Con_Error(L"[-] Enumeration stopped, error=");
        Con_Dec(last);
        Con_Error(L" (");
        Con_Hex32(last);
        Con_Error(L")\r\n");
        ExitProcess(last);
    }

    Con_Print(L"[*] Visible entries: ");
    Con_Dec(count);
    Con_Print(L"\r\n");
}

void __stdcall Entry(void) {
    Con_Init();

    int argc = ParseCommandLine();
    wchar_t** argv = g_argv;

    if (argc < 2) {
        PrintUsage();
        ExitProcess(1);
    }

    const wchar_t* cmd = argv[1];

    // ── Driver-only commands (no path required) ─────────────────────────
    if (weq(cmd, L"start")) {
        Con_Print(L"[*] Loading driver...\r\n");
        if (DriverSession_Start()) {
            Con_Print(L"[+] Driver running.\r\n");
            ExitProcess(0);
        }
        Con_Error(L"[!] Failed to start driver.\r\n");
        ExitProcess(1);
    }

    if (weq(cmd, L"stop")) {
        DriverSession_Stop();
        Con_Print(L"[*] Driver stop requested.\r\n");
        ExitProcess(0);
    }

    if (weq(cmd, L"cleanup")) {
        DriverSession_Cleanup();
        Con_Print(L"[*] Cleanup complete.\r\n");
        ExitProcess(0);
    }

    // ── File operation commands (path required) ─────────────────────────
    if (argc < 3) {
        PrintUsage();
        ExitProcess(1);
    }

    // Determine operation
    DWORD op = 0;
    const wchar_t* verb = NULL;

    if (weq(cmd, L"list") || weq(cmd, L"ls")) {
        op = 4; verb = L"LIST";
    } else if (weq(cmd, L"delete") || weq(cmd, L"del")) {
        op = 1; verb = L"DELETE";
    } else if (weq(cmd, L"rename") || weq(cmd, L"ren") || weq(cmd, L"move")) {
        op = 2; verb = L"RENAME";
    } else if (weq(cmd, L"copy") || weq(cmd, L"cp")) {
        op = 3; verb = L"COPY";
    } else {
        Con_Error(L"[!] Unknown command: ");
        Con_Error(cmd);
        Con_Error(L"\r\n");
        ExitProcess(1);
    }

    // Reassemble path from argv fragments (handles unquoted paths with spaces).
    // For rename/copy: last argument is dest, everything before is source path.
    // For delete: all arguments after command form the path.
    wchar_t path[MAX_PATH * 2];
    wchar_t dest_buf[MAX_PATH * 2];
    wchar_t* dest = NULL;
    path[0] = 0;
    dest_buf[0] = 0;

    int path_end = argc;       // exclusive: argv[2..path_end-1] = source path
    if ((op == 2 || op == 3) && argc > 3) {
        path_end = argc - 1;   // quoted path case: last arg is dest
        for (int i = 3; i < argc; i++) {
            if (is_abs_path_start(argv[i])) {
                path_end = i;  // unquoted case: second absolute path starts dest
                break;
            }
        }
    }

    for (int i = 2; i < path_end; i++) {
        if (i > 2) wcat_ch(path, L' ', MAX_PATH * 2);
        wcat(path, argv[i], MAX_PATH * 2);
    }

    if (op == 2 || op == 3) {
        if (path_end >= argc) {
            Con_Error(L"[!] Rename/copy requires destination path.\r\n");
            ExitProcess(1);
        }
        for (int i = path_end; i < argc; i++) {
            if (i > path_end) wcat_ch(dest_buf, L' ', MAX_PATH * 2);
            wcat(dest_buf, argv[i], MAX_PATH * 2);
        }
        dest = dest_buf;
    }

    // Strip trailing backslash (unless root like C:\)
    {
        int pl = wlen(path);
        if (pl > 3 && path[pl - 1] == L'\\') path[pl - 1] = 0;
        if (dest) {
            int dl = wlen(dest);
            if (dl > 3 && dest[dl - 1] == L'\\') dest[dl - 1] = 0;
        }
    }

    // Safety: refuse to delete critical system paths
    if (op == 1) {
        static const wchar_t* blocked[] = {
            L"c:\\windows", L"c:\\program files", L"c:\\program files (x86)",
            L"c:\\users", L"c:\\programdata", L"c:\\system volume information",
            L"c:\\$recycle.bin", L"c:\\", L"d:\\", L"e:\\",
            NULL
        };
        for (int b = 0; blocked[b]; b++) {
            if (weq(path, blocked[b])) {
                Con_Error(L"[!] Refusing to delete critical path: ");
                Con_Error(path);
                Con_Error(L"\r\n");
                ExitProcess(1);
            }
        }
    }

    if (op == 4) {
        Con_Print(L"[*] LIST: ");
        Con_Print(path);
        Con_Print(L"\r\n");
        ListVisibleEntries(path);
        ExitProcess(0);
    }

    // Registry hive files are locked by the kernel registry manager, not WdFilter.
    // The IOCTL path returns ERROR_SHARING_VIOLATION for them regardless of driver state.
    // Intercept here and route copy -> RegSaveKeyExW; block delete/rename with a clear message.
    {
        wchar_t hiveSubKey[512];
        HKEY    hiveRoot = NULL;
        if (HiveIO_IsHivePath(path, &hiveRoot, hiveSubKey, 512)) {
            if (op == 1 || op == 2) {
                Con_Error(L"[!] Path is a mounted registry hive.\r\n");
                Con_Error(L"    Delete/rename not supported while the hive is loaded.\r\n");
                Con_Error(L"    Use 'copy' to export a consistent snapshot via RegSaveKeyExW.\r\n");
                ExitProcess(ERROR_SHARING_VIOLATION);
            }
            // op == 3 (copy)
            if (!dest) {
                Con_Error(L"[!] Copy requires a destination path.\r\n");
                ExitProcess(1);
            }
            Con_Print(L"[*] Registry hive detected -> RegSaveKeyExW path (no driver needed)\r\n");
            Con_Print(L"[*] COPY (hive): ");
            Con_Print(path);
            Con_Print(L" -> ");
            Con_Print(dest);
            Con_Print(L"\r\n");

            DWORD herr = HiveIO_Save(hiveRoot, hiveSubKey, dest);
            if (herr == 0) {
                Con_Print(L"[+] Success.\r\n");
                ExitProcess(0);
            }
            Con_Error(L"[-] Failed, error=");
            Con_Dec(herr);
            Con_Error(L" (");
            Con_Hex32(herr);
            Con_Error(L")\r\n");
            ExitProcess(herr);
        }
    }

    // Atomic driver session: extract → service → start → device
    HANDLE hDev = DriverSession_Begin();
    if (hDev == INVALID_HANDLE_VALUE) {
        DWORD dle = GetLastError();
        Con_Error(L"[!] Cannot start driver session (error=");
        Con_Dec(dle);
        Con_Error(L"). Run as Administrator.\r\n");
        ExitProcess(1);
    }

    // Execute
    Con_Print(L"[*] ");
    Con_Print(verb);
    Con_Print(L": ");
    Con_Print(path);
    if (dest) { Con_Print(L" -> "); Con_Print(dest); }
    Con_Print(L"\r\n");

    DWORD err = 0;
    switch (op) {
        case 1: err = DeviceIO_Delete(hDev, path); break;
        case 2: err = DeviceIO_Rename(hDev, path, dest); break;
        case 3: err = DeviceIO_Copy(hDev, path, dest); break;
    }

    // Atomic cleanup: close device → stop → delete service → remove driver
    DriverSession_End(hDev);

    if (err == 0) {
        Con_Print(L"[+] Success.\r\n");
        ExitProcess(0);
    }

    Con_Error(L"[-] Failed, error=");
    Con_Dec(err);
    Con_Error(L" (");
    Con_Hex32(err);
    Con_Error(L")\r\n");
    ExitProcess(err);
}
