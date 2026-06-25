// DriverExtract.c
// FDI in-memory decompression of the driver payload from icon+CAB resource.
//
// IDR_DRIVER_PAYLOAD layout (built by build.ps1):
//   [ICO header (ICON_HEADER_SIZE bytes)] [LZX-CAB containing forceio.dat]
//
// © WESMAR Marek Wesołowski

#include "DriverExtract.h"
#include "GenIconSize.h"
#include "Resource.h"

#include <fdi.h>

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#pragma comment(lib, "Cabinet.lib")

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) *d++ = *s++;
    return dst;
}

// ─── FDI in-memory state ───────────────────────────────────────────────────

static struct {
    const BYTE* cabPtr;
    SIZE_T      cabOff;
    SIZE_T      cabEnd;
    BYTE*       outPtr;
    SIZE_T      outUsed;
    SIZE_T      outCap;
} g_fdi;

// ─── FDI callbacks ─────────────────────────────────────────────────────────

static LPVOID DIAMONDAPI fdi_alloc(ULONG cb) {
    return HeapAlloc(GetProcessHeap(), 0, cb);
}

static void DIAMONDAPI fdi_free(LPVOID pv) {
    HeapFree(GetProcessHeap(), 0, pv);
}

static INT_PTR DIAMONDAPI fdi_open(char* pszFile, int oflag, int pmode) {
    (void)pszFile; (void)oflag; (void)pmode;
    return 1;
}

static UINT DIAMONDAPI fdi_read(INT_PTR hf, void* pv, UINT cb) {
    (void)hf;
    SIZE_T avail = g_fdi.cabEnd - g_fdi.cabOff;
    if (cb > (UINT)avail) cb = (UINT)avail;
    if (cb > 0) { memcpy(pv, g_fdi.cabPtr + g_fdi.cabOff, cb); g_fdi.cabOff += cb; }
    return cb;
}

static UINT DIAMONDAPI fdi_write(INT_PTR hf, void* pv, UINT cb) {
    (void)hf;
    if (g_fdi.outUsed + cb > g_fdi.outCap) return 0;
    memcpy(g_fdi.outPtr + g_fdi.outUsed, pv, cb);
    g_fdi.outUsed += cb;
    return cb;
}

static int DIAMONDAPI fdi_close(INT_PTR hf) {
    (void)hf;
    return 0;
}

static long DIAMONDAPI fdi_seek(INT_PTR hf, long dist, int seektype) {
    (void)hf;
    long newPos;
    if (seektype == SEEK_SET)      newPos = dist;
    else if (seektype == SEEK_CUR) newPos = (long)g_fdi.cabOff + dist;
    else                           newPos = (long)g_fdi.cabEnd + dist;
    if (newPos < 0) newPos = 0;
    if ((SIZE_T)newPos > g_fdi.cabEnd) newPos = (long)g_fdi.cabEnd;
    g_fdi.cabOff = (SIZE_T)newPos;
    return newPos;
}

static INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin) {
    (void)pfdin;
    if (fdint == fdintCOPY_FILE)       return 1;
    if (fdint == fdintCLOSE_FILE_INFO) return TRUE;
    return 0;
}

// ─── Public API ────────────────────────────────────────────────────────────

BOOL DriverExtract_Deploy(const wchar_t* destFullPath) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_DRIVER_PAYLOAD), RT_RCDATA);
    if (!hRes) return FALSE;

    DWORD totalSize = SizeofResource(NULL, hRes);
    if (totalSize <= ICON_HEADER_SIZE + 4) return FALSE;

    HGLOBAL hGlob = LoadResource(NULL, hRes);
    if (!hGlob) return FALSE;
    const BYTE* raw = (const BYTE*)LockResource(hGlob);
    if (!raw) return FALSE;

    SIZE_T cabSize = totalSize - ICON_HEADER_SIZE;

    static const SIZE_T kOutCap = 256 * 1024;
    BYTE* outBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, kOutCap);
    if (!outBuf) return FALSE;

    g_fdi.cabPtr  = raw + ICON_HEADER_SIZE;
    g_fdi.cabOff  = 0;
    g_fdi.cabEnd  = cabSize;
    g_fdi.outPtr  = outBuf;
    g_fdi.outUsed = 0;
    g_fdi.outCap  = kOutCap;

    ERF erf;
    erf.erfOper = 0; erf.erfType = 0; erf.fError = FALSE;

    HFDI hfdi = FDICreate(fdi_alloc, fdi_free, fdi_open, fdi_read,
                          fdi_write, fdi_close, fdi_seek, cpuUNKNOWN, &erf);
    if (!hfdi) { HeapFree(GetProcessHeap(), 0, outBuf); return FALSE; }

    BOOL ok = FDICopy(hfdi, (char*)"memory.cab", (char*)"", 0, fdi_notify, NULL, NULL);
    FDIDestroy(hfdi);

    if (!ok || g_fdi.outUsed == 0) {
        HeapFree(GetProcessHeap(), 0, outBuf);
        return FALSE;
    }

    HANDLE hFile = CreateFileW(destFullPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, outBuf);
        return (GetFileAttributesW(destFullPath) != INVALID_FILE_ATTRIBUTES);
    }

    DWORD written = 0;
    DWORD toWrite = (DWORD)g_fdi.outUsed;
    BOOL writeOk = WriteFile(hFile, outBuf, toWrite, &written, NULL);
    CloseHandle(hFile);

    HeapFree(GetProcessHeap(), 0, outBuf);
    g_fdi.outPtr  = NULL;
    g_fdi.outUsed = 0;

    return (writeOk && written == toWrite);
}
