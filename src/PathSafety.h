// Fail-closed path checks for destructive file operations.
#pragma once
#include <windows.h>

#define FORCEIO_PATH_CAPACITY 264

static __inline DWORD PathSafety_Resolve(const wchar_t* path, wchar_t* full) {
    DWORD length = 0;
    if (!path || !path[0]) return ERROR_INVALID_NAME;
    while (length < FORCEIO_PATH_CAPACITY && path[length]) length++;
    if (length >= FORCEIO_PATH_CAPACITY) return ERROR_FILENAME_EXCED_RANGE;
    length = GetFullPathNameW(path, FORCEIO_PATH_CAPACITY, full, NULL);
    if (!length) return GetLastError();
    if (length >= FORCEIO_PATH_CAPACITY) return ERROR_FILENAME_EXCED_RANGE;
    // Device namespaces need different parsing and are deliberately rejected.
    if (full[0] == L'\\' && full[1] == L'\\' &&
        (full[2] == L'?' || full[2] == L'.')) return ERROR_INVALID_NAME;
    for (DWORD i = 0; i < length; i++) {
        if (full[i] == L'/') full[i] = L'\\';
    }
    while (length > 3 && full[length - 1] == L'\\') full[--length] = 0;
    return ERROR_SUCCESS;
}

static __inline DWORD PathSafety_Check(const wchar_t* path) {
    wchar_t full[FORCEIO_PATH_CAPACITY];
    DWORD err = PathSafety_Resolve(path, full);
    DWORD start = 3;
    if (err) return err;
    if (full[0] == L'\\' && full[1] == L'\\') {
        // Skip the server name; check the share root and every child.
        start = 2;
        while (full[start] && full[start] != L'\\') start++;
        if (!full[start]) return ERROR_INVALID_NAME;
        start++;
    }
    for (DWORD i = start; ; i++) {
        wchar_t saved = full[i];
        if (saved != L'\\' && saved != 0) continue;
        full[i] = 0;
        DWORD attr = GetFileAttributesW(full);
        DWORD attrError = (attr == INVALID_FILE_ATTRIBUTES) ? GetLastError() : 0;
        full[i] = saved;
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (attrError != ERROR_FILE_NOT_FOUND && attrError != ERROR_PATH_NOT_FOUND)
                return attrError;
        } else if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
            return ERROR_NOT_SUPPORTED;
        }
        if (!saved) break;
    }
    return ERROR_SUCCESS;
}

static __inline DWORD PathSafety_CheckPair(const wchar_t* src, const wchar_t* dst) {
    wchar_t source[FORCEIO_PATH_CAPACITY], target[FORCEIO_PATH_CAPACITY];
    DWORD err = PathSafety_Check(src);
    if (err) return err;
    err = PathSafety_Check(dst);
    if (err) return err;
    err = PathSafety_Resolve(src, source);
    if (err) return err;
    err = PathSafety_Resolve(dst, target);
    if (err) return err;
    if (CompareStringOrdinal(source, -1, target, -1, TRUE) == CSTR_EQUAL)
        return ERROR_INVALID_PARAMETER;
    DWORD attr = GetFileAttributesW(source);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD attrError = GetLastError();
        // This is a safety check, not a source-existence check. The caller may
        // resolve a logical source through another API (for example a hive).
        // Ordinary file operations still check existence in their own backend.
        if (attrError == ERROR_FILE_NOT_FOUND || attrError == ERROR_PATH_NOT_FOUND)
            return ERROR_SUCCESS;
        return attrError;
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        int length = 0, targetLength = 0;
        while (source[length]) length++;
        while (target[targetLength]) targetLength++;
        if (targetLength > length &&
            (source[length - 1] == L'\\' || target[length] == L'\\') &&
            CompareStringOrdinal(source, length, target, length, TRUE) == CSTR_EQUAL)
            return ERROR_INVALID_PARAMETER;
    }
    return ERROR_SUCCESS;
}
