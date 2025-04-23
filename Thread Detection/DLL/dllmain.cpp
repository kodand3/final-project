#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <set>
#include <vector>
#include "MinHook.h"

std::set<LPVOID> whitelist;
std::vector<std::vector<BYTE>> shellcodeSignatures = {
    {0x90, 0x90, 0x90}, // NOP sled
    {0xCC, 0xCC, 0xCC}  // INT 3 breakpoints
};

bool ScanMemoryForShellcode(HANDLE hProcess, LPVOID startAddress) {
    BYTE buffer[256];
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, startAddress, buffer, sizeof(buffer), &bytesRead)) {
        for (const auto& signature : shellcodeSignatures) {
            for (size_t i = 0; i <= bytesRead - signature.size(); i++) {
                if (memcmp(buffer + i, signature.data(), signature.size()) == 0) return true;
            }
        }
    }
    return false;
}

bool IsSuspiciousAddress(HANDLE hProcess, LPVOID startAddress) {
    if (whitelist.count(startAddress)) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi))) {
        if ((mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) || mbi.Type == MEM_PRIVATE) {
            // Check if address belongs to a loaded module
            HMODULE hMods[1024];
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    MODULEINFO modInfo;
                    GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo));
                    if (startAddress >= modInfo.lpBaseOfDll && startAddress < (LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
                        whitelist.insert(startAddress);
                        return false;
                    }
                }
            }
            if (ScanMemoryForShellcode(hProcess, startAddress)) return true;
        }
    }
    return false;
}

void HandleSuspiciousThread(HANDLE hThread, LPVOID startAddress) {
    std::cout << "[ALERT] Shellcode detected at: " << startAddress << ". Terminating thread...\n";
    TerminateThread(hThread, 1);
    CloseHandle(hThread);
}

typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

CreateThread_t fpCreateThread = nullptr;
CreateRemoteThread_t fpCreateRemoteThread = nullptr;
NtCreateThreadEx_t fpNtCreateThreadEx = nullptr;

HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE hThread = fpCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (IsSuspiciousAddress(GetCurrentProcess(), lpStartAddress)) {
        HandleSuspiciousThread(hThread, lpStartAddress);
    }
    return hThread;
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE hThread = fpCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (IsSuspiciousAddress(hProcess, lpStartAddress)) {
        HandleSuspiciousThread(hThread, lpStartAddress);
    }
    return hThread;
}

NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStack, SIZE_T MaximumStackSize, PVOID AttributeList) {
    NTSTATUS status = fpNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStack, MaximumStackSize, AttributeList);
    if (IsSuspiciousAddress(ProcessHandle, lpStartAddress)) {
        HandleSuspiciousThread(*ThreadHandle, lpStartAddress);
    }
    return status;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MH_Initialize();
        MH_CreateHook(&CreateThread, &HookedCreateThread, reinterpret_cast<void**>(&fpCreateThread));
        MH_EnableHook(&CreateThread);
        MH_CreateHook(&CreateRemoteThread, &HookedCreateRemoteThread, reinterpret_cast<void**>(&fpCreateRemoteThread));
        MH_EnableHook(&CreateRemoteThread);
        MH_CreateHook(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx"), &HookedNtCreateThreadEx, reinterpret_cast<void**>(&fpNtCreateThreadEx));
        MH_EnableHook(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx"));
    }
    return TRUE;
}

