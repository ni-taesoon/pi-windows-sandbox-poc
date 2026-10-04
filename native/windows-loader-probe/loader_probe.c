/* Fixed diagnostic child. No CRT, arguments, Python exports, process creation or policy changes. */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

/* MSVC may emit this helper for checked array indexing even without CRT linkage.
 * Preserve its fatal range-check semantics; never return or attempt recovery. */
__declspec(noreturn) void __cdecl __report_rangecheckfailure(void) {
    __fastfail(FAST_FAIL_RANGE_CHECK_FAILURE);
}

static char line_buffer[96];
static WCHAR system_library[32768];
static const char hex_digits[] = "0123456789ABCDEF";
static void emit(const char *stage, DWORD code) {
    DWORD n = 0, done = 0, written;
    const char *prefix = "LOADER_PROBE ";
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    while (*prefix) line_buffer[n++] = *prefix++;
    while (*stage && n < 70) line_buffer[n++] = *stage++;
    line_buffer[n++] = ' '; line_buffer[n++] = '0'; line_buffer[n++] = 'x';
    for (DWORD i = 0; i < 8; ++i) line_buffer[n++] = hex_digits[(code >> (28 - 4*i)) & 15];
    line_buffer[n++] = '\n';
    if (output == NULL || output == INVALID_HANDLE_VALUE) ExitProcess(0xE0010001);
    while (done < n) {
        if (!WriteFile(output,line_buffer+done,n-done,&written,NULL) || written == 0) ExitProcess(0xE0010002);
        done += written;
    }
}
static void load_fixed(const WCHAR *path, const char *stage) {
    HMODULE module = LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == NULL) {
        DWORD error = GetLastError();
        emit(stage,error);
        ExitProcess(0xE0020001);
    }
    emit(stage,0);
    /* Keep the fixed modules loaded until process exit; no export calls. */
}
void WINAPI lab_probe_entry(void) {
    DWORD length;
    const WCHAR *tail = L"\\ucrtbase.dll";
    emit("entry",0);
    Sleep(100); /* Bounded independent observer opportunity; still inside the 15s job deadline. */
    length = GetSystemDirectoryW(system_library,32768);
    if (length == 0) { DWORD error=GetLastError(); emit("system-directory",error); ExitProcess(error ? error : 1); }
    if (length >= 32768-16) { emit("system-directory",ERROR_INSUFFICIENT_BUFFER); ExitProcess(ERROR_INSUFFICIENT_BUFFER); }
    while (*tail) system_library[length++] = *tail++;
    system_library[length] = 0;
    load_fixed(system_library,"ucrtbase");
    load_fixed(L"C:\\PiSandboxLab\\runtime\\vcruntime140.dll","vcruntime140");
    load_fixed(L"C:\\PiSandboxLab\\runtime\\python312.dll","python312");
    emit("complete",0);
    ExitProcess(0);
}
