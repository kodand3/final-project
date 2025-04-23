#include <Windows.h>
#include <iostream>

DWORD WINAPI MaliciousCode(LPVOID lpParam) {
    MessageBox(NULL, L"Shellcode executed!", L"Test", MB_OK);
    return 0;
}

int main() {
    DWORD processId = GetCurrentProcessId();
    std::cout << "[INFO] Running in Process ID: " << processId << "\n";

    std::cout << "[INFO] Allocating RWX memory for shellcode...\n";
    Sleep(10000);  // 1-second delay

    LPVOID shellcode = VirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL) {
        std::cerr << "[ERROR] Failed to allocate memory.\n";
        return 1;
    }

    std::cout << "[INFO] Writing NOP sled to memory...\n";
    Sleep(10000);  // 1-second delay
    memset(shellcode, 0x90, 16); // NOP sled

    std::cout << "[INFO] Copying malicious code to memory...\n";
    Sleep(10000);  // 1-second delay
    memcpy((BYTE*)shellcode + 16, (BYTE*)MaliciousCode, 512); // Copy malicious function

    std::cout << "[INFO] Creating thread to execute shellcode...\n";
    Sleep(10000);  // 1-second delay
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "[ERROR] Failed to create thread.\n";
        return 1;
    }

    std::cout << "[INFO] Shellcode thread created successfully in Process ID: " << processId << "\n";
    Sleep(10000);  // 1-second delay

    WaitForSingleObject(hThread, INFINITE);
    VirtualFree(shellcode, 0, MEM_RELEASE);
    std::cout << "[INFO] MALWARE INSTALLATION DONE SUCCESSFULLY ........ " << "\n";
    return 0;
}

