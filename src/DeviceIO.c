// DeviceIO.c
// IOCTL protocol implementation for IObitUnlocker.sys.
//
// The driver validates the calling process by reading its EXE from disk and
// computing two checksums (XOR == 0x2B, alternating add/sub == 0x00A88677).
// The build script appends correction bytes to satisfy this check at compile time.
//
// © WESMAR Marek Wesołowski

#include "DeviceIO.h"

#define DEVICE_PATH      L"\\\\.\\IObitUnlockerDevice"
#define IOCTL_ULK_OP     0x00222124u
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
    ULK_BUFFER buf;
    memset(&buf, 0, sizeof(buf));

    wcopy_safe(buf.SourcePath, src, 264);
    if (dst && dst[0])
        wcopy_safe(buf.DestPath, dst, 264);

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

static void path_join(wchar_t* dst, const wchar_t* dir, const wchar_t* name, int max) {
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
}

static DWORD DeleteRecursive(HANDLE hDev, const wchar_t* path);
static DWORD CopyRecursive(HANDLE hDev, const wchar_t* src, const wchar_t* dst);

static DWORD DeleteDirectoryContents(HANDLE hDev, const wchar_t* dir) {
    wchar_t pattern[MAX_PATH + 4];
    path_join(pattern, dir, L"*", MAX_PATH + 4);

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
        path_join(child, dir, fd.cFileName, MAX_PATH + 4);

        DWORD err = DeleteRecursive(hDev, child);
        if (err && !result) result = err;
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return result;
}

static DWORD DeleteRecursive(HANDLE hDev, const wchar_t* path) {
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return 0;

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        DWORD err = DeleteDirectoryContents(hDev, path);
        if (err) return err;
    }

    return SendOperation(hDev, path, NULL, OP_DELETE);
}

DWORD DeviceIO_Delete(HANDLE hDev, const wchar_t* path) {
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError();

    return DeleteRecursive(hDev, path);
}

DWORD DeviceIO_Rename(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
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

DWORD DeviceIO_Copy(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
    return CopyRecursive(hDev, src, dst);
}

static DWORD CopyDirectoryContents(HANDLE hDev, const wchar_t* srcDir, const wchar_t* dstDir) {
    wchar_t pattern[MAX_PATH + 4];
    path_join(pattern, srcDir, L"*", MAX_PATH + 4);

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
        path_join(childSrc, srcDir, fd.cFileName, MAX_PATH + 4);
        path_join(childDst, dstDir, fd.cFileName, MAX_PATH + 4);

        DWORD err = CopyRecursive(hDev, childSrc, childDst);
        if (err && !result) result = err;
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return result;
}

static DWORD CopyRecursive(HANDLE hDev, const wchar_t* src, const wchar_t* dst) {
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
