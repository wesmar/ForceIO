// DeviceIO.c
// IOCTL protocol implementation for IObitUnlocker.sys.
//
// The driver validates the calling process by reading its EXE from disk and
// computing two checksums (XOR == 0x2B, alternating add/sub == 0x00A88677).
// The build script appends correction bytes to satisfy this check at compile time.
//
// © WESMAR Marek Wesołowski

#include "DeviceIO.h"
#include "PathSafety.h"

#define DEVICE_PATH      L"\\\\.\\IObitUnlockerDevice"
#define IOCTL_ULK_OP     0x00222124u
#define IOCTL_ULK_QRY    0x00222128u
#define BUFFER_SIZE      0x428

#define OP_DELETE    1
#define OP_RENAME    2
#define OP_MOVE      3
#define OP_COPY      4

#pragma pack(push, 1)
typedef struct {
    wchar_t SourcePath[264];   // +0x000 (0x210 bytes)
    wchar_t DestPath[264];     // +0x210 (0x210 bytes)
    ULONG   OpType;            // +0x420
    ULONG   Flags;             // +0x424
} ULK_BUFFER;
#pragma pack(pop)

typedef char static_assert_size[(sizeof(ULK_BUFFER) == BUFFER_SIZE) ? 1 : -1];

#pragma function(memset)
void* memset(void* dest, int val, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) *p++ = (unsigned char)val;
    return dest;
}

static void wcopy_safe(wchar_t* dst, const wchar_t* src, int max_chars) {
    int i = 0;
    while (i < max_chars - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static DWORD SendOperation(HANDLE hDev, const wchar_t* src, const wchar_t* dst, ULONG op) {
    DWORD safetyError = dst ? PathSafety_CheckPair(src, dst) : PathSafety_Check(src);
    if (safetyError) return safetyError;

    wchar_t fullSrc[FORCEIO_PATH_CAPACITY];
    wchar_t fullDst[FORCEIO_PATH_CAPACITY];
    DWORD resSrc = PathSafety_Resolve(src, fullSrc);
    const wchar_t* targetSrc = (resSrc == ERROR_SUCCESS) ? fullSrc : src;
    const wchar_t* targetDst = dst;
    if (dst && dst[0]) {
        DWORD resDst = PathSafety_Resolve(dst, fullDst);
        targetDst = (resDst == ERROR_SUCCESS) ? fullDst : dst;
    }

    ULK_BUFFER buf;
    memset(&buf, 0, sizeof(buf));

    wcopy_safe(buf.SourcePath, targetSrc, 264);
    if (targetDst && targetDst[0])
        wcopy_safe(buf.DestPath, targetDst, 264);

    buf.OpType = op;
    buf.Flags  = 3;

    ULONG out = 0;
    DWORD ret = 0;

    SetLastError(0);
    DeviceIoControl(hDev, IOCTL_ULK_OP, &buf, BUFFER_SIZE, &out, 4, &ret, NULL);
    return GetLastError();
}

HANDLE DeviceIO_Open(void) {
    return CreateFileW(DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
}

void DeviceIO_Close(HANDLE hDev) {
    if (hDev && hDev != INVALID_HANDLE_VALUE)
        CloseHandle(hDev);
}

static int wlen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) p++;
    return (int)(p - s);
}

static DWORD path_join(wchar_t* dst, const wchar_t* dir, const wchar_t* name, int max) {
    int dirLength = wlen(dir), nameLength = wlen(name);
    int separator = dirLength > 0 && dir[dirLength - 1] != L'\\';
    if (dirLength + separator + nameLength >= max)
        return ERROR_FILENAME_EXCED_RANGE;
    wcopy_safe(dst, dir, max);
    int len = wlen(dst);
    if (len > 0 && len < max - 2 && dst[len - 1] != L'\\') {
        dst[len] = L'\\';
        dst[len + 1] = 0;
        len++;
    }
    int i = 0;
    while (len + i < max - 1 && name[i]) {
        dst[len + i] = name[i];
        i++;
    }
    dst[len + i] = 0;
    return ERROR_SUCCESS;
}

static DWORD DeleteRecursive(HANDLE hDev, const wchar_t* path);
static DWORD CopyRecursive(HANDLE hDev, const wchar_t* src, const wchar_t* dst);

static DWORD DeleteDirectoryContents(HANDLE hDev, const wchar_t* dir) {
    wchar_t pattern[MAX_PATH + 4];
    DWORD joinError = path_join(pattern, dir, L"*", MAX_PATH + 4);
    if (joinError) return joinError;

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return GetLastError();

    DWORD result = 0;
    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
            continue;

        wchar_t child[MAX_PATH + 4];
        joinError = path_join(child, dir, fd.cFileName, MAX_PATH + 4);
        if (joinError) { result = joinError; break; }

        DWORD err = DeleteRecursive(hDev, child);
        if (err && !result) result = err;
    } while (FindNextFileW(hFind, &fd));

    DWORD enumerationError = GetLastError();
    FindClose(hFind);
    if (!result && enumerationError != ERROR_NO_MORE_FILES) result = enumerationError;
    return result;
}

static DWORD DeleteRecursive(HANDLE hDev, const wchar_t* path) {
    DWORD safetyError = PathSafety_Check(path);
    if (safetyError) return safetyError;
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError();

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        DWORD err = DeleteDirectoryContents(hDev, path);
        if (err) return err;
    }

    return SendOperation(hDev, path, NULL, OP_DELETE);
}

DWORD DeviceIO_Delete(HANDLE hDev, const wchar_t* path) {
    DWORD safetyError = PathSafety_Check(path);
    if (safetyError) return safetyError;

    wchar_t fullPath[FORCEIO_PATH_CAPACITY];
    DWORD resErr = PathSafety_Resolve(path, fullPath);
    const wchar_t* targetPath = (resErr == ERROR_SUCCESS) ? fullPath : path;

    DWORD attr = GetFileAttributesW(targetPath);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError();

    return DeleteRecursive(hDev, targetPath);
}

DWORD DeviceIO_Rename(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
    DWORD safetyError = PathSafety_CheckPair(src, dst);
    if (safetyError) return safetyError;
    DWORD err = SendOperation(hDev, src, dst, OP_RENAME);
    if (err == 0)
        return 0;

    if (MoveFileExW(src, dst, MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH))
        return 0;

    if (GetFileAttributesW(dst) != INVALID_FILE_ATTRIBUTES)
        return ERROR_ALREADY_EXISTS;

    err = SendOperation(hDev, src, dst, OP_MOVE);
    if (err == 0)
        return 0;

    DWORD attr = GetFileAttributesW(src);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        DWORD copyErr = SendOperation(hDev, src, dst, OP_COPY);
        if (copyErr == 0)
            return SendOperation(hDev, src, NULL, OP_DELETE);
    }

    return err;
}

// IOCTL 0x222128 input: just the path in SourcePath (first 264 WCHARs).
// Output: single WCHAR string "exe_path,PID|exe_path,PID|..." (pipe after each entry).
// Output buffer must be at least 64 KB; driver returns ERROR_INSUFFICIENT_BUFFER otherwise.
// This function allocates the output buffer with VirtualAlloc; caller must
// VirtualFree(*outBuf, 0, MEM_RELEASE) on success (*outBuf != NULL).
DWORD DeviceIO_QueryLocks(HANDLE hDev, const wchar_t* path,
                          wchar_t** outBuf, DWORD* outChars) {
    *outBuf   = NULL;
    *outChars = 0;

    wchar_t fullPath[FORCEIO_PATH_CAPACITY];
    DWORD resErr = PathSafety_Resolve(path, fullPath);
    const wchar_t* targetPath = (resErr == ERROR_SUCCESS) ? fullPath : path;

    int i;
    for (i = 0; i < 263 && targetPath[i]; i++) {}
    if (targetPath[i]) return ERROR_FILENAME_EXCED_RANGE;

    wchar_t inPath[264];
    for (i = 0; i < 264; i++) inPath[i] = 0;
    for (i = 0; i < 263 && targetPath[i]; i++) inPath[i] = targetPath[i];

    // Try output sizes: 64 KB → 128 KB → 256 KB → 512 KB
    static const DWORD kSizes[] = { 0x10000, 0x20000, 0x40000, 0x80000, 0 };
    int si;
    for (si = 0; kSizes[si]; si++) {
        wchar_t* buf = (wchar_t*)VirtualAlloc(NULL, kSizes[si],
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
        if (!buf) return GetLastError();

        DWORD returned = 0;
        SetLastError(0);
        DeviceIoControl(hDev, IOCTL_ULK_QRY,
                        inPath, (DWORD)(264 * sizeof(wchar_t)),
                        buf, kSizes[si], &returned, NULL);
        DWORD err = GetLastError();

        if (err == ERROR_INSUFFICIENT_BUFFER) {
            VirtualFree(buf, 0, MEM_RELEASE);
            continue;
        }
        if (err != 0) {
            VirtualFree(buf, 0, MEM_RELEASE);
            return err;
        }

        *outBuf   = buf;
        *outChars = returned / (DWORD)sizeof(wchar_t);
        return 0;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

DWORD DeviceIO_Copy(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
    DWORD safetyError = PathSafety_CheckPair(src, dst);
    if (safetyError) return safetyError;
    return CopyRecursive(hDev, src, dst);
}

static DWORD CopyDirectoryContents(HANDLE hDev, const wchar_t* srcDir, const wchar_t* dstDir) {
    wchar_t pattern[MAX_PATH + 4];
    DWORD joinError = path_join(pattern, srcDir, L"*", MAX_PATH + 4);
    if (joinError) return joinError;

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return GetLastError();

    DWORD result = 0;
    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
            continue;

        wchar_t childSrc[MAX_PATH + 4];
        wchar_t childDst[MAX_PATH + 4];
        joinError = path_join(childSrc, srcDir, fd.cFileName, MAX_PATH + 4);
        if (!joinError) joinError = path_join(childDst, dstDir, fd.cFileName, MAX_PATH + 4);
        if (joinError) { result = joinError; break; }

        DWORD err = CopyRecursive(hDev, childSrc, childDst);
        if (err && !result) result = err;
    } while (FindNextFileW(hFind, &fd));

    DWORD enumerationError = GetLastError();
    FindClose(hFind);
    if (!result && enumerationError != ERROR_NO_MORE_FILES) result = enumerationError;
    return result;
}

static DWORD CopyRecursive(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
    DWORD safetyError = PathSafety_CheckPair(src, dst);
    if (safetyError) return safetyError;
    DWORD attr = GetFileAttributesW(src);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError();

    DWORD dstAttr = GetFileAttributesW(dst);

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        DWORD err = SendOperation(hDev, src, dst, OP_COPY);
        if (err == 0)
            return 0;

        if (dstAttr == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(dst, NULL))
                return GetLastError();
        } else if (!(dstAttr & FILE_ATTRIBUTE_DIRECTORY)) {
            return ERROR_ALREADY_EXISTS;
        }

        return CopyDirectoryContents(hDev, src, dst);
    }

    if (dstAttr != INVALID_FILE_ATTRIBUTES)
        return ERROR_ALREADY_EXISTS;

    return SendOperation(hDev, src, dst, OP_COPY);
}
