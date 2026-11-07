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
#include "PathSafety.h"

int _fltused = 0;

static int wlen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) p++;
    return (int)(p - s);
}

static void wcat(wchar_t* dst, const wchar_t* src, int max) {
    int base = wlen(dst);
    if (base + wlen(src) >= max) {
        Con_Error(L"[!] Path is too long; refusing to truncate it.\r\n");
        ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    }
    int i = 0;
    while (base + i < max - 1 && src[i]) { dst[base + i] = src[i]; i++; }
    dst[base + i] = 0;
}

static void wcat_ch(wchar_t* dst, wchar_t ch, int max) {
    int base = wlen(dst);
    if (base >= max - 1) {
        Con_Error(L"[!] Path is too long; refusing to truncate it.\r\n");
        ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    }
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

static int has_wildcard(const wchar_t* s) {
    if (!s) return 0;
    while (*s) {
        if (*s == L'*' || *s == L'?') return 1;
        s++;
    }
    return 0;
}

static int split_wildcard_path(const wchar_t* path, wchar_t* dir, int dir_max, const wchar_t** pattern) {
    const wchar_t* last_bs = NULL;
    for (const wchar_t* p = path; *p; p++) {
        if (*p == L'\\') last_bs = p;
    }
    if (!last_bs) return 0;

    for (const wchar_t* p = path; p < last_bs; p++) {
        if (*p == L'*' || *p == L'?') return 0;
    }

    *pattern = last_bs + 1;
    if (!**pattern) return 0;

    int dir_len = (int)(last_bs - path);
    if (dir_len == 2 && path[1] == L':') dir_len = 3;

    if (dir_len >= dir_max) return 0;
    for (int i = 0; i < dir_len; i++) dir[i] = path[i];
    dir[dir_len] = 0;
    return 1;
}

static void PrintUsage(void) {
    Con_Print(L"ForceIO - minifilter-bypass file operations via signed driver\r\n");
    Con_Print(L"WESMAR - Marek Wesolowski https://kvc.pl\r\n\r\n");
    Con_Print(L"Usage: ForceIO <command> <path> [dest]\r\n\r\n");
    Con_Print(L"Commands:\r\n");
    Con_Print(L"  list    <path>       List visible directory entries (diagnostic)\r\n");
    Con_Print(L"  locks   <path>       Show which processes lock the file\r\n");
    Con_Print(L"  delete  <path>       Force-delete file (bypasses WdFilter)\r\n");
    Con_Print(L"  rename  <src> <dst>  Force-rename/move file\r\n");
    Con_Print(L"  copy    <src> <dst>  Copy locked file\r\n");
    Con_Print(L"  start                Load driver only\r\n");
    Con_Print(L"  stop                 Stop driver\r\n");
    Con_Print(L"  cleanup              Stop driver, remove service, delete temp files\r\n");
}

// Print processes locking a file (IOCTL 0x222128 result).
// buf: "exe_path,PID|exe_path,PID|..." WCHAR string, nChars wide chars.
static DWORD PrintLockList(wchar_t* buf, DWORD nChars) {
    if (nChars == 0) {
        Con_Print(L"[+] No processes currently lock this file.\r\n");
        return ERROR_SUCCESS;
    }

    DWORD count = 0;
    wchar_t* entry = buf;
    wchar_t* end   = buf + nChars;

    while (entry < end && *entry) {
        // find end of this entry (next '|' or end of buffer)
        wchar_t* pipe = entry;
        while (pipe < end && *pipe && *pipe != L'|') pipe++;
        if (pipe == end) {
            Con_Error(L"[-] Incomplete lock-list entry; missing terminator.\r\n");
            return ERROR_INVALID_DATA;
        }

        // find the last ',' to split path from PID
        // start one before pipe to avoid reading past valid data
        wchar_t* comma = (pipe > entry) ? pipe - 1 : entry;
        while (comma > entry && *comma != L',') comma--;

        // print: "  PID  exe_name  (full_path)"
        Con_Print(L"  PID ");
        if (comma > entry) {
            // PID: null-terminate at pipe so Con_Print stops there
            wchar_t savedPipe = *pipe;
            *pipe = 0;
            Con_Print(comma + 1);
            *pipe = savedPipe;

            // find exe basename (last '\' before comma)
            wchar_t* bs = comma;
            while (bs > entry && *bs != L'\\') bs--;
            if (*bs == L'\\') bs++;

            // basename + full path both end at comma — one null-termination covers both
            wchar_t savedComma = *comma;
            *comma = 0;
            Con_Print(L"  ");
            Con_Print(bs);        // basename: bs..comma
            Con_Print(L"  (");
            Con_Print(entry);     // full path: entry..comma
            Con_Print(L")");
            *comma = savedComma;
        } else {
            // no comma — print raw entry, null-terminate at pipe
            wchar_t savedPipe = *pipe;
            *pipe = 0;
            Con_Print(entry);
            *pipe = savedPipe;
        }
        Con_Print(L"\r\n");
        count++;

        entry = pipe;
        if (entry < end && *entry == L'|') entry++;
    }

    Con_Print(L"[*] "); Con_Dec(count); Con_Print(L" process(es) locking the file.\r\n");
    return ERROR_SUCCESS;
}

#define MAX_ARGS 16
static wchar_t g_cmdline[4096];
static wchar_t* g_argv[MAX_ARGS];

static int ParseCommandLine(void) {
    const wchar_t* raw = GetCommandLineW();
    int i = 0;
    while (raw[i] && i < 4095) { g_cmdline[i] = raw[i]; i++; }
    if (raw[i]) {
        Con_Error(L"[!] Command line is too long.\r\n");
        ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    }
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
    while (*p == L' ' || *p == L'\t') p++;
    if (*p) {
        Con_Error(L"[!] Too many arguments.\r\n");
        ExitProcess(ERROR_BAD_ARGUMENTS);
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

    // Disable WOW64 file system redirection on 64-bit systems so 32-bit ForceIO
    // can access real System32 paths (e.g. System32\winevt\Logs) without redirection to SysWOW64.
    PVOID oldWow64 = NULL;
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        typedef BOOL (WINAPI *pfnWow64Disable)(PVOID*);
        pfnWow64Disable fnDisable = (pfnWow64Disable)GetProcAddress(hK32, "Wow64DisableWow64FsRedirection");
        if (fnDisable) fnDisable(&oldWow64);
    }

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

    if (weq(cmd, L"locks") || weq(cmd, L"unlock")) {
        static wchar_t lockPath[MAX_PATH * 2];
        static wchar_t resolvedLock[FORCEIO_PATH_CAPACITY];
        lockPath[0] = 0;
        for (int i = 2; i < argc; i++) {
            if (i > 2) wcat_ch(lockPath, L' ', MAX_PATH * 2);
            wcat(lockPath, argv[i], MAX_PATH * 2);
        }
        int lpl = wlen(lockPath);
        if (lpl > 3 && lockPath[lpl - 1] == L'\\') lockPath[lpl - 1] = 0;

        DWORD rerr = PathSafety_Resolve(lockPath, resolvedLock);
        const wchar_t* targetLock = (rerr == ERROR_SUCCESS) ? resolvedLock : lockPath;

        if (has_wildcard(targetLock)) {
            static wchar_t wildcard_dir[MAX_PATH * 2];
            const wchar_t* pattern = NULL;
            if (!split_wildcard_path(targetLock, wildcard_dir, MAX_PATH * 2, &pattern)) {
                Con_Error(L"[!] Unsafe or unsupported wildcard path.\r\n");
                ExitProcess(ERROR_INVALID_NAME);
            }
            DWORD safetyError = PathSafety_Check(wildcard_dir);
            if (safetyError) {
                Con_Error(L"[!] Unsafe directory, error=");
                Con_Dec(safetyError);
                Con_Error(L"\r\n");
                ExitProcess(safetyError);
            }

            HANDLE hDev = DriverSession_Begin();
            if (hDev == INVALID_HANDLE_VALUE) {
                DWORD dle = GetLastError();
                Con_Error(L"[!] Cannot start driver session (error=");
                Con_Dec(dle);
                Con_Error(L"). Run as Administrator.\r\n");
                ExitProcess(1);
            }

            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(targetLock, &fd);
            if (hFind == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                DriverSession_End(hDev);
                Con_Error(L"[-] No matching files found, error=");
                Con_Dec(err);
                Con_Error(L"\r\n");
                ExitProcess(err);
            }

            static wchar_t child_path[MAX_PATH * 2];
            do {
                if (fd.cFileName[0] == L'.' &&
                    (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                    continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    continue;

                child_path[0] = 0;
                wcat(child_path, wildcard_dir, MAX_PATH * 2);
                int dlen = wlen(child_path);
                if (dlen > 0 && child_path[dlen - 1] != L'\\') {
                    wcat_ch(child_path, L'\\', MAX_PATH * 2);
                }
                wcat(child_path, fd.cFileName, MAX_PATH * 2);

                Con_Print(L"[*] LOCKS: ");
                Con_Print(child_path);
                Con_Print(L"\r\n");

                wchar_t* lockBuf = NULL;
                DWORD lockChars = 0;
                DWORD lerr = DeviceIO_QueryLocks(hDev, child_path, &lockBuf, &lockChars);
                if (lerr == 0) {
                    PrintLockList(lockBuf, lockChars);
                } else {
                    Con_Error(L"[-] Query failed, error=");
                    Con_Dec(lerr);
                    Con_Error(L"\r\n");
                }
                if (lockBuf) VirtualFree(lockBuf, 0, MEM_RELEASE);
            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);
            DriverSession_End(hDev);
            ExitProcess(0);
        }

        Con_Print(L"[*] LOCKS: ");
        Con_Print(targetLock);
        Con_Print(L"\r\n");

        HANDLE hDev = DriverSession_Begin();
        if (hDev == INVALID_HANDLE_VALUE) {
            DWORD dle = GetLastError();
            Con_Error(L"[!] Cannot start driver session (error=");
            Con_Dec(dle);
            Con_Error(L"). Run as Administrator.\r\n");
            ExitProcess(1);
        }

        wchar_t* lockBuf   = NULL;
        DWORD    lockChars = 0;
        DWORD    lerr = DeviceIO_QueryLocks(hDev, targetLock, &lockBuf, &lockChars);
        DriverSession_End(hDev);

        if (lerr != 0) {
            Con_Error(L"[-] Query failed, error=");
            Con_Dec(lerr);
            Con_Error(L" (");
            Con_Hex32(lerr);
            Con_Error(L")\r\n");
            ExitProcess(lerr);
        }

        lerr = PrintLockList(lockBuf, lockChars);
        if (lockBuf) VirtualFree(lockBuf, 0, MEM_RELEASE);
        ExitProcess(lerr);
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
    static wchar_t path[MAX_PATH * 2];
    static wchar_t dest_buf[MAX_PATH * 2];
    static wchar_t resolved_path[FORCEIO_PATH_CAPACITY];
    static wchar_t resolved_dest[FORCEIO_PATH_CAPACITY];
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

    // Canonicalize paths to absolute so relative paths work from any working directory
    // and kernel driver receives fully qualified NT paths (\??\C:\...).
    {
        DWORD resErr = PathSafety_Resolve(path, resolved_path);
        if (resErr == ERROR_SUCCESS) {
            path[0] = 0;
            wcat(path, resolved_path, MAX_PATH * 2);
        }
        if (dest) {
            DWORD destErr = PathSafety_Resolve(dest, resolved_dest);
            if (destErr == ERROR_SUCCESS) {
                dest_buf[0] = 0;
                wcat(dest_buf, resolved_dest, MAX_PATH * 2);
                dest = dest_buf;
            }
        }
    }

    // Wildcard batch support (for delete)
    if (has_wildcard(path)) {
        if (op != 1) {
            Con_Error(L"[!] Wildcards are only supported for 'delete' and 'locks'.\r\n");
            ExitProcess(ERROR_NOT_SUPPORTED);
        }

        static wchar_t wildcard_dir[MAX_PATH * 2];
        const wchar_t* pattern = NULL;
        if (!split_wildcard_path(path, wildcard_dir, MAX_PATH * 2, &pattern)) {
            Con_Error(L"[!] Unsafe or unsupported wildcard path.\r\n");
            ExitProcess(ERROR_INVALID_NAME);
        }

        DWORD safetyError = PathSafety_Check(wildcard_dir);
        if (safetyError) {
            Con_Error(L"[!] Unsafe directory, error=");
            Con_Dec(safetyError);
            Con_Error(L"\r\n");
            ExitProcess(safetyError);
        }

        // Safety: refuse to delete wildcard in critical system roots
        static const wchar_t* blocked_roots[] = {
            L"c:\\", L"c:\\windows", L"c:\\program files", L"c:\\program files (x86)",
            L"c:\\users", L"c:\\system volume information", NULL
        };
        for (int b = 0; blocked_roots[b]; b++) {
            if (weq(wildcard_dir, blocked_roots[b])) {
                Con_Error(L"[!] Refusing wildcard delete in critical system path: ");
                Con_Error(wildcard_dir);
                Con_Error(L"\r\n");
                ExitProcess(1);
            }
        }

        HANDLE hDev = DriverSession_Begin();
        if (hDev == INVALID_HANDLE_VALUE) {
            DWORD dle = GetLastError();
            Con_Error(L"[!] Cannot start driver session (error=");
            Con_Dec(dle);
            Con_Error(L"). Run as Administrator.\r\n");
            ExitProcess(1);
        }

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(path, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            DriverSession_End(hDev);
            Con_Error(L"[-] No matching files found, error=");
            Con_Dec(err);
            Con_Error(L" (");
            Con_Hex32(err);
            Con_Error(L")\r\n");
            ExitProcess(err);
        }

        DWORD total = 0, success = 0, failed = 0;
        static wchar_t child_path[MAX_PATH * 2];
        do {
            if (fd.cFileName[0] == L'.' &&
                (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            child_path[0] = 0;
            wcat(child_path, wildcard_dir, MAX_PATH * 2);
            int dlen = wlen(child_path);
            if (dlen > 0 && child_path[dlen - 1] != L'\\') {
                wcat_ch(child_path, L'\\', MAX_PATH * 2);
            }
            wcat(child_path, fd.cFileName, MAX_PATH * 2);

            total++;
            Con_Print(L"[*] DELETE: ");
            Con_Print(child_path);
            Con_Print(L"\r\n");

            DWORD err = DeviceIO_Delete(hDev, child_path);
            if (err == 0) {
                Con_Print(L"[+] Success.\r\n");
                success++;
            } else {
                Con_Error(L"[-] Failed, error=");
                Con_Dec(err);
                Con_Error(L" (");
                Con_Hex32(err);
                Con_Error(L")\r\n");
                failed++;
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        DriverSession_End(hDev);

        Con_Print(L"[*] Summary: ");
        Con_Dec(success);
        Con_Print(L" deleted, ");
        Con_Dec(failed);
        Con_Print(L" failed (total ");
        Con_Dec(total);
        Con_Print(L")\r\n");

        ExitProcess(failed ? 1 : 0);
    }

    // Reject unsafe paths before accessing registry hives or starting a session.
    if (op != 4) {
        DWORD safetyError = dest ? PathSafety_CheckPair(path, dest) : PathSafety_Check(path);
        if (safetyError) {
            Con_Error(L"[!] Unsafe or unsupported path, error=");
            Con_Dec(safetyError);
            Con_Error(L"\r\n");
            ExitProcess(safetyError);
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

            BOOL overwriteConfirmed = FALSE;
            DWORD destinationAttributes = GetFileAttributesW(dest);
            if (destinationAttributes != INVALID_FILE_ATTRIBUTES) {
                if (destinationAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    Con_Error(L"[!] Destination is a directory.\r\n");
                    ExitProcess(ERROR_ALREADY_EXISTS);
                }
                if (!Con_ConfirmOverwrite(dest)) {
                    Con_Error(L"\r\nOperation cancelled.\r\n");
                    ExitProcess(ERROR_CANCELLED);
                }
                overwriteConfirmed = TRUE;
            }
            DWORD herr = HiveIO_Save(hiveRoot, hiveSubKey, dest, overwriteConfirmed);
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
