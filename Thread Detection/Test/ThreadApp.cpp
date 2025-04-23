#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <tchar.h>
#include <set>

std::set<DWORD> injectedProcesses;

typedef enum _PROCESS_STATE {
    ProcessRunning = 0,
    ProcessSuspended = 1,
} PROCESS_STATE;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

// Enable SeDebugPrivilege
BOOL SetDebugPrivilege(BOOL bEnable) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

// Check if the process is 64-bit
BOOL Is64BitProcess(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);
    return !isWow64;
}

// Check if the process is suspended
BOOL IsProcessSuspended(HANDLE hProcess) {
    if (!NtQueryInformationProcess) return FALSE;

    ULONG state;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0x2E, &state, sizeof(state), NULL);
    if (((NTSTATUS)(status) >= 0) && state == ProcessSuspended) return TRUE;
    return FALSE;
}

// Check if the process is a system process
BOOL IsSystemProcess(DWORD processId) {
    if (processId == 0 || processId == 4) return TRUE;
    return FALSE;
}

// Inject the DLL
BOOL InjectDLL(DWORD dwProcessId, const char* dllPath) {
    if (injectedProcesses.find(dwProcessId) != injectedProcesses.end()) return TRUE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess) return FALSE;

    if (!Is64BitProcess(hProcess)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (IsProcessSuspended(hProcess)) {
        std::cout << "[INFO] Skipping suspended process: " << dwProcessId << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteBuf, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (WaitForSingleObject(hThread, 5000) == WAIT_TIMEOUT) {
        TerminateThread(hThread, 0);
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    injectedProcesses.insert(dwProcessId);
    std::cout << "[SUCCESS] DLL injected into process ID: " << dwProcessId << "\n";
    return TRUE;
}

int main() {
    const char* dllPath = "C:\\Projects\\ThreadDLL\\x64\\Debug\\ThreadDLL.dll";
    std::cout << "[INFO] Starting DLL injection for all 64-bit processes...\n";

    if (!SetDebugPrivilege(TRUE)) {
        std::cerr << "[ERROR] Failed to set debug privilege.\n";
        return 1;
    }

    while (true) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) break;

        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnap, &pe)) {
            do {
                if (!IsSystemProcess(pe.th32ProcessID)) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        if (Is64BitProcess(hProcess) && pe.th32ProcessID != GetCurrentProcessId()) {
                            std::cout << "[INFO] Found process: " << pe.szExeFile << " (PID: " << pe.th32ProcessID << ")\n";
                            InjectDLL(pe.th32ProcessID, dllPath);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
        Sleep(2000);  // Check every 2 seconds
    }
    return 0;
}

