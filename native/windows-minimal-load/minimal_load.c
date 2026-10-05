/* Fixed compatibility observation only. No arguments, DLL export calls or probes.
 * No CRT: a fresh process calls the documented loader once, reports the result,
 * and exits. Windows reclaims the module at process termination. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void write_text(const char *text, DWORD length) {
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, length, &written, NULL)
        || written != length) {
        ExitProcess(2);
    }
}

void minimal_load_entry(void) {
    HMODULE module;
    DWORD error;
    static char digits[10];
    static WCHAR system_directory[MAX_PATH];
    static const WCHAR expected_directory[] = L"C:\\Windows\\System32";
    DWORD directory_length;
    DWORD i;
    int preloaded;
    DWORD count = 0;
    static const char prefix[] =
        "{\"schemaVersion\":1,\"library\":\"C:\\\\Windows\\\\System32\\\\bcrypt.dll\",\"loaded\":";
    static const char success[] = "true,\"win32Error\":0";
    static const char failure[] = "false,\"win32Error\":";
    static const char already_loaded[] = ",\"preloaded\":true}\n";
    static const char not_loaded[] = ",\"preloaded\":false}\n";
    static const char invalid_directory[] = "{\"schemaVersion\":1,\"status\":\"SYSTEM_DIRECTORY_MISMATCH\"}\n";

    directory_length = GetSystemDirectoryW(system_directory, MAX_PATH);
    if (directory_length != (sizeof(expected_directory) / sizeof(WCHAR)) - 1) {
        write_text(invalid_directory, (DWORD)(sizeof(invalid_directory) - 1));
        ExitProcess(3);
    }
    for (i = 0; i < directory_length; ++i) {
        WCHAR actual = system_directory[i];
        WCHAR expected = expected_directory[i];
        if (actual >= L'A' && actual <= L'Z') actual += L'a' - L'A';
        if (expected >= L'A' && expected <= L'Z') expected += L'a' - L'A';
        if (actual != expected) {
            write_text(invalid_directory, (DWORD)(sizeof(invalid_directory) - 1));
            ExitProcess(3);
        }
    }
    /* Borrowed handle only: do not unload it or treat it as fresh initialization. */
    preloaded = GetModuleHandleW(L"bcrypt.dll") != NULL;
    module = LoadLibraryExW(L"C:\\Windows\\System32\\bcrypt.dll", NULL,
                            LOAD_LIBRARY_SEARCH_SYSTEM32);
    error = module ? ERROR_SUCCESS : GetLastError(); /* Capture before any output API. */
    write_text(prefix, (DWORD)(sizeof(prefix) - 1));
    if (module) {
        write_text(success, (DWORD)(sizeof(success) - 1));
        if (preloaded) write_text(already_loaded, (DWORD)(sizeof(already_loaded) - 1));
        else write_text(not_loaded, (DWORD)(sizeof(not_loaded) - 1));
        ExitProcess(0);
    }
    write_text(failure, (DWORD)(sizeof(failure) - 1));
    do {
        digits[count++] = (char)('0' + error % 10);
        error /= 10;
    } while (error != 0);
    while (count != 0) {
        write_text(&digits[--count], 1);
    }
    if (preloaded) write_text(already_loaded, (DWORD)(sizeof(already_loaded) - 1));
    else write_text(not_loaded, (DWORD)(sizeof(not_loaded) - 1));
    ExitProcess(1);
}
