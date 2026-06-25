// HiveIO.c
// Registry hive copy via RegSaveKeyExW.
//
// When source path matches a mounted hive in the kernel hivelist the IOCTL path
// is useless (ERROR_SHARING_VIOLATION from the registry manager, not WdFilter).
// RegSaveKeyExW asks the registry manager to flush a consistent snapshot to disk,
// which works even on SAM/SECURITY/SYSTEM that are otherwise inaccessible.
//
// © WESMAR Marek Wesołowski

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "HiveIO.h"

// ── helpers (no CRT) ─────────────────────────────────────────────────────────

static int hlen(const wchar_t* s) {
    const wchar_t* p = s; while (*p) p++; return (int)(p - s);
}

static void hcopy(wchar_t* dst, const wchar_t* src, int max) {
    int i = 0;
    while (i < max - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

// Case-insensitive wide-string equality (ASCII range only, sufficient for NT paths).
static int hicmp(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? *a + 32 : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

// ── path conversion ───────────────────────────────────────────────────────────

// "C:\Windows\System32\config\SAM"  ->  "\Device\HarddiskVolumeN\Windows\System32\config\SAM"
// Returns 0 if path is not a drive-letter path or device name lookup fails.
static int PathToNT(const wchar_t* path, wchar_t* ntPath, int ntMax) {
    if (hlen(path) < 3) return 0;
    wchar_t c0 = path[0];
    if (!((c0 >= L'A' && c0 <= L'Z') || (c0 >= L'a' && c0 <= L'z'))) return 0;
    if (path[1] != L':') return 0;
    if (path[2] != L'\\' && path[2] != L'/') return 0;

    wchar_t drive[3] = { c0, L':', 0 };
    wchar_t device[512];
    if (!QueryDosDeviceW(drive, device, 512)) return 0;

    int dlen = hlen(device);
    const wchar_t* rest = path + 2;   // "\foo\bar" (starts with backslash)
    int rlen = hlen(rest);
    if (dlen + rlen + 1 >= ntMax) return 0;

    hcopy(ntPath, device, ntMax);
    int i = 0;
    for (; rest[i] && dlen + i < ntMax - 1; i++)
        ntPath[dlen + i] = rest[i];
    ntPath[dlen + i] = 0;
    return 1;
}

// ── registry path parser ──────────────────────────────────────────────────────

// Hivelist value names look like:
//   \REGISTRY\MACHINE\SAM         -> HKLM, subkey "SAM"
//   \REGISTRY\USER\S-1-5-21-...-500  -> HKU, subkey "S-1-5-21-...-500"
//   \REGISTRY\USER\.DEFAULT       -> HKU, subkey ".DEFAULT"
//   \REGISTRY\MACHINE\BCD00000000 -> HKLM, subkey "BCD00000000"
//   \REGISTRY\WC\...              -> skip (container hives, not standard users)
static int ParseHiveRegPath(const wchar_t* name, HKEY* rootOut, wchar_t* subOut, int subMax) {
    static const wchar_t kM[] = L"\\REGISTRY\\MACHINE\\";
    static const wchar_t kU[] = L"\\REGISTRY\\USER\\";
    int mlen = (int)(sizeof(kM) / sizeof(wchar_t) - 1);
    int ulen = (int)(sizeof(kU) / sizeof(wchar_t) - 1);
    int nlen = hlen(name);

    if (nlen > mlen) {
        int ok = 1;
        for (int i = 0; i < mlen; i++) {
            wchar_t a = name[i], b = kM[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { ok = 0; break; }
        }
        if (ok) { *rootOut = HKEY_LOCAL_MACHINE; hcopy(subOut, name + mlen, subMax); return 1; }
    }

    if (nlen > ulen) {
        int ok = 1;
        for (int i = 0; i < ulen; i++) {
            wchar_t a = name[i], b = kU[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { ok = 0; break; }
        }
        if (ok) { *rootOut = HKEY_USERS; hcopy(subOut, name + ulen, subMax); return 1; }
    }

    return 0;
}

// ── public API ────────────────────────────────────────────────────────────────

int HiveIO_IsHivePath(const wchar_t* path, HKEY* rootKeyOut,
                      wchar_t* subKeyOut, int subMax) {
    // Static to keep stack frame < 4KB (avoids __chkstk with /NODEFAULTLIB).
    static wchar_t ntPath[1024];
    static wchar_t vName[512];
    static wchar_t vData[1024];

    if (!PathToNT(path, ntPath, 1024)) return 0;

    HKEY hList = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\hivelist",
                      0, KEY_QUERY_VALUE, &hList) != ERROR_SUCCESS)
        return 0;

    int found = 0;
    DWORD idx = 0;

    for (;;) {
        DWORD cchName = 512, cbData = sizeof(vData), type = 0;
        LSTATUS s = RegEnumValueW(hList, idx++, vName, &cchName, NULL, &type,
                                  (BYTE*)vData, &cbData);
        if (s == ERROR_NO_MORE_ITEMS) break;
        if (s != ERROR_SUCCESS) continue;
        // Skip HARDWARE entry (empty data) and non-string values
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || cbData < 4) continue;

        if (hicmp(vData, ntPath)) {
            wchar_t sk[512];
            HKEY rk = NULL;
            if (ParseHiveRegPath(vName, &rk, sk, 512)) {
                *rootKeyOut = rk;
                hcopy(subKeyOut, sk, subMax);
                found = 1;
            }
            break;
        }
    }

    RegCloseKey(hList);
    return found;
}

DWORD HiveIO_Save(HKEY rootKey, const wchar_t* subKey, const wchar_t* destPath) {
    // SE_BACKUP_NAME is required by RegSaveKeyExW
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValueW(NULL, SE_BACKUP_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }

    HKEY hKey = NULL;
    LSTATUS s = RegOpenKeyExW(rootKey, subKey, 0, KEY_READ, &hKey);
    if (s != ERROR_SUCCESS) return (DWORD)s;

    DeleteFileW(destPath);   // RegSaveKeyExW returns ERROR_ALREADY_EXISTS if file exists
    s = RegSaveKeyExW(hKey, destPath, NULL, REG_LATEST_FORMAT);
    RegCloseKey(hKey);
    return (s == ERROR_SUCCESS) ? 0 : (DWORD)s;
}
