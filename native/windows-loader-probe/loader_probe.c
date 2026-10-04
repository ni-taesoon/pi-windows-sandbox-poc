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
/* Only fixed call-site tails are accepted; no user input or PATH resolution. */
static void load_system(const WCHAR *tail, const char *stage) {
    DWORD length = GetSystemDirectoryW(system_library,32768);
    if (length == 0) { DWORD error=GetLastError(); emit("system-directory",error); ExitProcess(error ? error : 1); }
    if (length >= 32768-32) { emit("system-directory",ERROR_INSUFFICIENT_BUFFER); ExitProcess(ERROR_INSUFFICIENT_BUFFER); }
    while (*tail) {
        if (length >= 32767) { emit("system-directory",ERROR_INSUFFICIENT_BUFFER); ExitProcess(ERROR_INSUFFICIENT_BUFFER); }
        system_library[length++] = *tail++;
    }
    system_library[length] = 0;
    load_fixed(system_library,stage);
}
/* Read-only self-access checks. Handles are never used to modify any object. */
typedef LONG (NTAPI *lab_open_token_fn)(HANDLE, ACCESS_MASK, PHANDLE);
static void record_handle(HANDLE handle, const char *stage) {
    DWORD error = handle == NULL ? GetLastError() : 0;
    if (handle != NULL && !CloseHandle(handle)) {
        DWORD close_error = GetLastError();
        emit("self-handle-close-win32",close_error);
        ExitProcess(0xE0030001);
    }
    emit(stage,error);
}
static void token_access(lab_open_token_fn open_token, ACCESS_MASK rights, const char *stage) {
    HANDLE token = NULL;
    LONG status = open_token(GetCurrentProcess(),rights,&token);
    if (status >= 0) {
        if (token == NULL || !CloseHandle(token)) {
            emit("self-token-close-win32",token == NULL ? ERROR_INVALID_HANDLE : GetLastError());
            ExitProcess(0xE0030001);
        }
    }
    emit("self-token-requested-mask",rights);
    emit(stage,(DWORD)status);
}
static void self_access(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    lab_open_token_fn open_token;
    if (ntdll == NULL) { DWORD error=GetLastError(); emit("self-ntdll-win32",error); ExitProcess(0xE0030002); }
    /* The one fixed resolver avoids pre-entry advapi32/sechost initialization. */
    open_token = (lab_open_token_fn)GetProcAddress(ntdll,"NtOpenProcessToken");
    if (open_token == NULL) { DWORD error=GetLastError(); emit("self-resolver-win32",error); ExitProcess(0xE0030002); }
    record_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentProcessId()),"self-process-query-win32");
    record_handle(OpenProcess(PROCESS_DUP_HANDLE,FALSE,GetCurrentProcessId()),"self-process-duplicate-win32");
    record_handle(OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentThreadId()),"self-thread-query-win32");
    record_handle(OpenThread(THREAD_SET_THREAD_TOKEN,FALSE,GetCurrentThreadId()),"self-thread-settoken-win32");
    token_access(open_token,TOKEN_QUERY,"self-token-query-ntstatus");
    token_access(open_token,TOKEN_DUPLICATE,"self-token-duplicate-ntstatus");
    token_access(open_token,TOKEN_IMPERSONATE,"self-token-impersonate-ntstatus");
    token_access(open_token,TOKEN_QUERY | TOKEN_DUPLICATE,"self-token-queryduplicate-ntstatus");
    token_access(open_token,TOKEN_ADJUST_DEFAULT,"self-token-adjustdefault-ntstatus");
    token_access(open_token,TOKEN_ADJUST_PRIVILEGES,"self-token-adjustprivileges-ntstatus");
    token_access(open_token,READ_CONTROL,"self-token-readcontrol-ntstatus");
}
void WINAPI lab_probe_entry(void) {
    emit("entry",0);
    Sleep(100); /* Bounded independent observer opportunity; still inside the 15s job deadline. */
    load_system(L"\\ucrtbase.dll","ucrtbase");
    load_fixed(L"C:\\PiSandboxLab\\runtime\\vcruntime140.dll","vcruntime140");
    /* Diagnostic dependency-first order, not a claim about Windows loader order. */
    load_system(L"\\msvcrt.dll","msvcrt");
    load_system(L"\\rpcrt4.dll","rpcrt4");
    self_access();
    load_system(L"\\sechost.dll","sechost");
    load_system(L"\\advapi32.dll","advapi32");
    load_system(L"\\bcrypt.dll","bcrypt");
    load_system(L"\\version.dll","version");
    load_system(L"\\ws2_32.dll","ws2_32");
    load_fixed(L"C:\\PiSandboxLab\\runtime\\python312.dll","python312");
    emit("complete",0);
    ExitProcess(0);
}
