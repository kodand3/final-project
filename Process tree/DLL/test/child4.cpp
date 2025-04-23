#include <windows.h>
#include <iostream>
#include <string>

bool InjectDLL(DWORD pid, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID alloc = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!alloc) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, alloc, dllPath.c_str(), dllPath.size() + 1, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        alloc, 0, NULL);

    if (!hThread) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main() {
    std::cout << "[child4] PID: " << GetCurrentProcessId() << "\n";
    Sleep(500);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cout << "[child4] Launched cmd.exe [PID: " << pi.dwProcessId << "]\n";
        Sleep(500);
        InjectDLL(pi.dwProcessId, "C:\\Projects\\ProcHook.dll\\x64\\Debug\\ProcHook.dll.dll");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return 0;
}

