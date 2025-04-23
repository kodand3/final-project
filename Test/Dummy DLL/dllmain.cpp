#include <Windows.h>
#include <iostream>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        MessageBoxA(NULL, "Dummy DLL Loaded Successfully!", "Test", MB_OK);
    }
    return TRUE;
}

