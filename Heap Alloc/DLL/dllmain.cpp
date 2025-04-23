#include "heap_hook.h"
#include <windows.h>
#include <stdio.h>

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        printf("\n[DLLMAIN] Installing Hook ......... \n");
        InstallHook();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        RemoveHook();
    }
    return TRUE;
}

