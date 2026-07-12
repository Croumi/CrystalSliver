#include <windows.h>
#include <shlwapi.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int __cdecl _configthreadlocale(int per_thread_locale_type);

typedef void (*pi_generic_fn)(void);

static volatile pi_generic_fn pi_slots[32];
static volatile int pi_guard = 0;

void pad_imports_touch(void) {
    pi_slots[0]  = (pi_generic_fn)(void*)QueryPerformanceCounter;
    pi_slots[1]  = (pi_generic_fn)(void*)QueryPerformanceFrequency;
    pi_slots[2]  = (pi_generic_fn)(void*)GetSystemTimeAsFileTime;
    pi_slots[3]  = (pi_generic_fn)(void*)GetProcessHeap;
    pi_slots[4]  = (pi_generic_fn)(void*)HeapAlloc;
    pi_slots[5]  = (pi_generic_fn)(void*)HeapFree;
    pi_slots[6]  = (pi_generic_fn)(void*)GetVersion;
    pi_slots[7]  = (pi_generic_fn)(void*)GetConsoleMode;
    pi_slots[8]  = (pi_generic_fn)(void*)GetModuleHandleW;
    pi_slots[9]  = (pi_generic_fn)(void*)GetSystemInfo;
    pi_slots[10] = (pi_generic_fn)(void*)GetCurrentThreadId;
    pi_slots[11] = (pi_generic_fn)(void*)InitializeCriticalSection;
    pi_slots[12] = (pi_generic_fn)(void*)DeleteCriticalSection;
    pi_slots[13] = (pi_generic_fn)(void*)EnterCriticalSection;
    pi_slots[14] = (pi_generic_fn)(void*)LeaveCriticalSection;
    pi_slots[15] = (pi_generic_fn)(void*)Sleep;
    pi_slots[16] = (pi_generic_fn)(void*)PathFileExistsW;
    pi_slots[17] = (pi_generic_fn)(void*)PathIsRelativeW;
    pi_slots[18] = (pi_generic_fn)(void*)_configthreadlocale;

    if (pi_guard) {
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        LARGE_INTEGER qpf;
        QueryPerformanceFrequency(&qpf);
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        HANDLE heap = GetProcessHeap();
        void *p = HeapAlloc(heap, 0, 64);
        HeapFree(heap, 0, p);
        DWORD ver = GetVersion();
        (void)ver;
        DWORD mode = 0;
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
        HMODULE h = GetModuleHandleW(0);
        (void)h;
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD tid = GetCurrentThreadId();
        (void)tid;
        CRITICAL_SECTION cs;
        InitializeCriticalSection(&cs);
        EnterCriticalSection(&cs);
        LeaveCriticalSection(&cs);
        DeleteCriticalSection(&cs);
        Sleep(0);
        PathFileExistsW(L"");
        PathIsRelativeW(L"");
        _configthreadlocale(-1);
    }
}

#ifdef __cplusplus
}
#endif
