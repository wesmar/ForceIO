// Console.c
// No-CRT console output via WriteFile + WideCharToMultiByte.
// © WESMAR Marek Wesołowski

#include "Console.h"

static HANDLE hOut;
static HANDLE hErr;

static int wlen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) p++;
    return (int)(p - s);
}

static void emit(HANDLE h, const wchar_t* msg) {
    DWORD written;
    int len = wlen(msg);
    // Keep buffer under 4KB to avoid __chkstk
    char buf[1024];
    while (len > 0) {
        int chunk = (len > 400) ? 400 : len;
        int n = WideCharToMultiByte(CP_UTF8, 0, msg, chunk, buf, sizeof(buf) - 1, 0, 0);
        if (n > 0) WriteFile(h, buf, (DWORD)n, &written, 0);
        msg += chunk;
        len -= chunk;
    }
}

void Con_Init(void) {
    hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    hErr = GetStdHandle(STD_ERROR_HANDLE);
}

void Con_Print(const wchar_t* msg) { emit(hOut, msg); }
void Con_Error(const wchar_t* msg) { emit(hErr, msg); }

void Con_Hex32(unsigned long val) {
    wchar_t buf[11];
    buf[0] = L'0'; buf[1] = L'x';
    for (int i = 9; i >= 2; i--) {
        int nib = val & 0xF;
        buf[i] = (nib < 10) ? (wchar_t)(L'0' + nib) : (wchar_t)(L'A' + nib - 10);
        val >>= 4;
    }
    buf[10] = 0;
    Con_Print(buf);
}

void Con_Dec(unsigned long val) {
    wchar_t buf[16];
    int i = 14;
    buf[15] = 0;
    if (val == 0) { Con_Print(L"0"); return; }
    while (val > 0 && i >= 0) {
        buf[i--] = (wchar_t)(L'0' + (val % 10));
        val /= 10;
    }
    Con_Print(&buf[i + 1]);
}
