// Stager.c
// Dynamic in-flight mathematical checksum stager for ForceIO.
// © WESMAR Marek Wesołowski

#include "Stager.h"

void* memset(void* dest, int val, size_t count);

static void UIntToDecW(DWORD val, WCHAR* out) {
    WCHAR tmp[16];
    int i = 0;
    if (val == 0) {
        tmp[i++] = L'0';
    } else {
        while (val > 0) {
            tmp[i++] = (WCHAR)(L'0' + (val % 10));
            val /= 10;
        }
    }
    int j = 0;
    while (i > 0) {
        out[j++] = tmp[--i];
    }
    out[j] = 0;
}

static void ComputeChecksums(const unsigned char* data, DWORD len, unsigned char* outXor, unsigned int* outAlt) {
    unsigned char x = 0;
    unsigned int a = 0;
    for (DWORD i = 0; i < len; i++) {
        x ^= data[i];
        if ((i & 1) == 0) {
            a += (unsigned int)data[i];
        } else {
            a -= (unsigned int)data[i];
        }
    }
    *outXor = x;
    *outAlt = a;
}

BOOL Stager_EnsurePadded(DWORD* pExitCode) {
    // 1. If we are already running as the staged worker, execute directly.
    WCHAR envVal[8];
    if (GetEnvironmentVariableW(L"_FORCEIO_WORKER", envVal, 8) > 0) {
        return FALSE;
    }

    // 2. Locate own executable.
    static WCHAR selfPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return FALSE;
    }

    // 3. Open self for reading.
    HANDLE hSelf = CreateFileW(selfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hSelf, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hSelf);
        return FALSE;
    }

    // Allocate buffer for self + up to 131072 bytes of overlay padding
    DWORD maxAlloc = fileSize + 131072;
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, maxAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        CloseHandle(hSelf);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hSelf, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hSelf);
        return FALSE;
    }
    CloseHandle(hSelf);

    // 4. Check if current file already satisfies driver checksum requirements.
    unsigned char curXor = 0;
    unsigned int curAlt = 0;
    ComputeChecksums(buf, fileSize, &curXor, &curAlt);

    if (curXor == FORCEIO_TARGET_XOR && curAlt == FORCEIO_TARGET_ALT) {
        // Pre-padded standalone binary — proceed directly without spawning worker!
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    // 5. Compute dynamic mathematical padding.
    DWORD alignedSize = fileSize;
    if (alignedSize & 1) {
        buf[alignedSize++] = 0;
        ComputeChecksums(buf, alignedSize, &curXor, &curAlt);
    }

    unsigned int alt_need = FORCEIO_TARGET_ALT - curAlt;
    unsigned int bulk = alt_need / 255;
    unsigned int remain = alt_need % 255;
    unsigned char xor_after = (unsigned char)(curXor ^ ((bulk & 1) ? 0xFF : 0x00));
    unsigned char xor_need = (unsigned char)(xor_after ^ FORCEIO_TARGET_XOR);

    if (alignedSize + (bulk * 2) + 4 > maxAlloc) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    unsigned char b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    BOOL found = FALSE;
    for (int i0 = 0; i0 < 256 && !found; i0++) {
        for (int i2 = 0; i2 < 256 && !found; i2++) {
            int odd_sum = i0 + i2 - (int)remain;
            int odd_xor = i0 ^ i2 ^ (int)xor_need;
            if (odd_sum < 0 || odd_sum > 510) continue;
            int diff = odd_sum - odd_xor;
            if (diff < 0 || (diff & 1) != 0) continue;
            for (int i1 = 0; i1 < 256; i1++) {
                int i3 = odd_sum - i1;
                if (i3 >= 0 && i3 <= 255 && ((i1 ^ i3) == odd_xor)) {
                    b0 = (unsigned char)i0;
                    b1 = (unsigned char)i1;
                    b2 = (unsigned char)i2;
                    b3 = (unsigned char)i3;
                    found = TRUE;
                    break;
                }
            }
        }
    }

    if (!found) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    // Append bulk pairs (0xFF, 0x00)
    DWORD p = alignedSize;
    for (DWORD k = 0; k < bulk; k++) {
        buf[p++] = 0xFF;
        buf[p++] = 0x00;
    }
    buf[p++] = b0;
    buf[p++] = b1;
    buf[p++] = b2;
    buf[p++] = b3;
    DWORD totalPaddedSize = p;

    // 6. Build temporary executable path in %TEMP%.
    static WCHAR tempPath[MAX_PATH];
    DWORD tlen = GetTempPathW(MAX_PATH, tempPath);
    if (tlen == 0 || tlen >= MAX_PATH - 64) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    // Append: fio_wk_<PID>_<Tick>.exe
    WCHAR* end = tempPath + tlen;
    if (end > tempPath && *(end - 1) != L'\\') {
        *end++ = L'\\';
    }

    const WCHAR* prefix = L"fio_wk_";
    while (*prefix) *end++ = *prefix++;

    WCHAR pidStr[16];
    UIntToDecW(GetCurrentProcessId(), pidStr);
    WCHAR* s = pidStr;
    while (*s) *end++ = *s++;

    *end++ = L'_';

    WCHAR tickStr[16];
    UIntToDecW(GetTickCount(), tickStr);
    s = tickStr;
    while (*s) *end++ = *s++;

    const WCHAR* ext = L".exe";
    while (*ext) *end++ = *ext++;
    *end = 0;

    // 7. Write padded binary to temporary file.
    HANDLE hOut = CreateFileW(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL writeOk = WriteFile(hOut, buf, totalPaddedSize, &bytesWritten, NULL);
    CloseHandle(hOut);
    VirtualFree(buf, 0, MEM_RELEASE);

    if (!writeOk || bytesWritten != totalPaddedSize) {
        DeleteFileW(tempPath);
        return FALSE;
    }

    // 8. Launch child worker with inherited console handles and _FORCEIO_WORKER=1.
    SetEnvironmentVariableW(L"_FORCEIO_WORKER", L"1");

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    memset(&pi, 0, sizeof(pi));

    static WCHAR cmdBuffer[4096];
    const WCHAR* rawCmd = GetCommandLineW();
    int ci = 0;
    while (rawCmd[ci] && ci < 4095) {
        cmdBuffer[ci] = rawCmd[ci];
        ci++;
    }
    cmdBuffer[ci] = 0;

    BOOL cpOk = CreateProcessW(tempPath, cmdBuffer, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!cpOk) {
        DeleteFileW(tempPath);
        return FALSE;
    }

    // 9. Wait for worker to finish.
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 10. Clean up temporary worker executable immediately.
    DeleteFileW(tempPath);

    if (pExitCode) {
        *pExitCode = exitCode;
    }
    return TRUE;
}
