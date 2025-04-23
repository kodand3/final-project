#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <set>

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    std::cout << "[*] Enabling debug privilege...\n";

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[!] Failed to open process token. Error: " << GetLastError() << "\n";
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        std::cerr << "[!] Failed to lookup SE_DEBUG_NAME. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "[!] Failed to adjust token privileges. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    DWORD lastErr = GetLastError();
    if (lastErr == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "[!] SeDebugPrivilege not assigned. Run as Administrator.\n";
        return false;
    }

    std::cout << "[+] Debug privilege enabled.\n";
    CloseHandle(hToken);
    return true;
}

bool InjectDLL(DWORD processID, const char* dllPath) {
    std::cout << "[*] Injecting DLL into PID: " << processID << "...\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "[!] Failed to open PID: " << processID << ". Error: " << GetLastError() << "\n";
        return false;
    }

    void* pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "[!] Memory allocation failed for PID: " << processID << ". Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "[!] Failed to write DLL path to PID: " << processID << ". Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "[!] Failed to get LoadLibraryA address. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "[!] Failed to create remote thread in PID: " << processID << ". Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] DLL injection initiated for PID: " << processID << ".\n";

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

void InjectDLLIntoAllProcesses(const char* dllPath) {
    static std::set<DWORD> injectedProcesses;
    std::set<std::string> protectedProcesses = { "svchost.exe", "lsass.exe", "smss.exe", "csrss.exe", "winlogon.exe", "wininit.exe" };

    std::cout << "[*] Scanning all processes for DLL injection...\n";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create process snapshot. Error: " << GetLastError() << "\n";
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnapshot, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            // Convert WCHAR to std::string
            std::wstring wideExeName(pe.szExeFile);
            std::string exeName(wideExeName.begin(), wideExeName.end());

            // Check if it's a protected or already injected process
            if (pid > 4 && protectedProcesses.find(exeName) == protectedProcesses.end() && injectedProcesses.find(pid) == injectedProcesses.end()) {
                std::cout << "[*] Found process: " << exeName << " (PID: " << pid << "). Attempting injection...\n";

                if (InjectDLL(pid, dllPath)) {
                    injectedProcesses.insert(pid);
                    std::cout << "[+] DLL injection successful for PID: " << pid << " (" << exeName << ").\n";
                }
                else {
                    std::cerr << "[!] DLL injection failed for PID: " << pid << ".\n";
                }
            }
            else {
                std::cout << "[*] Skipped process: " << exeName << " (PID: " << pid << ").\n";
            }

        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        std::cerr << "[!] Failed to retrieve the first process entry. Error: " << GetLastError() << "\n";
    }

    CloseHandle(hSnapshot);
    std::cout << "[*] Process scan completed.\n";
}

int main() {
    const char* dllPath = "C:\\Projects\\CheckerDLL\\x64\\Debug\\CheckerDLL.dll";

    std::cout << "[*] Starting DLL injector...\n";

    if (!EnableDebugPrivilege()) {
        std::cerr << "[!] Failed to enable debug privilege. Exiting...\n";
        return 1;
    }

    std::cout << "[+] Injecting DLL into all running processes...\n";

    while (true) {
        InjectDLLIntoAllProcesses(dllPath);
        std::cout << "[*] Waiting 5 seconds before next scan...\n";
        Sleep(5000);
    }
    return 0;
}

