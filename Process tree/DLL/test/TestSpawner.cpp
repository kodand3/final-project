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

void LaunchAndInject(const std::string& exe, const std::string& args = "") {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    std::string cmd = exe + " " + args;

    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cout << "[+] Launched " << exe << " [PID: " << pi.dwProcessId << "]\n";
        Sleep(500);
        InjectDLL(pi.dwProcessId, "C:\\Projects\\ProcHook.dll\\x64\\Debug\\ProcHook.dll.dll"); // Must be in same dir
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "[-] Failed to launch " << exe << "\n";
    }
}

int main() {
    DWORD selfPid = GetCurrentProcessId();
    std::cout << "TestSpawner PID: " << selfPid << "\n";

    InjectDLL(selfPid, "C:\\Projects\\ProcHook.dll\\x64\\Debug\\ProcHook.dll.dll"); // Inject self

    //LaunchAndInject("notepad.exe");
    LaunchAndInject("C:\\Projects\\child1\\x64\\Debug\\child1.exe");
    LaunchAndInject("C:\\Projects\\child2\\x64\\Debug\\child2.exe");

    std::cout << "\nTestSpawner sleeping for 60 seconds...\n";
    Sleep(60000); // Sleep 60 sec

    return 0;
}

