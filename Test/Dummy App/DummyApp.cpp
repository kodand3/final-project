#include <Windows.h>
#include <iostream>

int main() {
    std::cout << "[*] DLL Path Injection Test\n";
    std::cout << "    PID: " << GetCurrentProcessId() << "\n";

    // STEP 1: Load your memExtractor.dll
    HMODULE hHook = LoadLibraryA("C:\\Projects\\memExtractor\\x64\\Debug\\memExtractor.dll");
    if (!hHook) {
        std::cerr << "[!] Failed to load memExtractor.dll. Error: " << GetLastError() << "\n";
    }
    else {
        std::cout << "[+] memExtractor loaded.\n";
    }

    // STEP 2: Write DLL path string into own memory
    const char* dllPath = "C:\\FakePath\\evil.dll";
    SIZE_T size = strlen(dllPath) + 1;
    HANDLE hProc = GetCurrentProcess();
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteMem, dllPath, size, NULL);
    std::cout << "[+] DLL path string written to memory.\n";

    std::cout << "[*] Done. Press Enter to exit.\n";
    std::cin.get();
    return 0;
}

