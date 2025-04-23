#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cmath>
#include "MinHook.h"

typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef ULONG(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);

WriteProcessMemory_t Original_WriteProcessMemory = NULL;
VirtualAllocEx_t Original_VirtualAllocEx = NULL;
VirtualProtectEx_t Original_VirtualProtectEx = NULL;
CreateRemoteThread_t Original_CreateRemoteThread = NULL;
NtCreateThreadEx_t Original_NtCreateThreadEx = NULL;
CreateFileMappingA_t Original_CreateFileMappingA = NULL;
MapViewOfFile_t Original_MapViewOfFile = NULL;
QueueUserAPC_t Original_QueueUserAPC = NULL;

std::string GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buffer[64];
    sprintf_s(buffer, "[%04d-%02d-%02d %02d:%02d:%02d] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

void LogEvent(const std::string& msg) {
    std::string line = GetTimestamp() + "[memExtractor] " + msg + "\n";

    OutputDebugStringA(line.c_str());

    FILE* f = nullptr;
    fopen_s(&f, "debug_log.txt", "a");
    if (f) {
        fwrite(line.c_str(), 1, line.length(), f);
        fclose(f);
    }
}

bool IsAsciiPrintable(const BYTE* data, SIZE_T size) {
    for (SIZE_T i = 0; i < size; ++i) {
        if (data[i] < 0x20 || data[i] > 0x7E) {
            if (data[i] != '\0' && data[i] != '\n' && data[i] != '\r')
                return false;
        }
    }
    return true;
}

bool IsUnicodePath(const BYTE* data, SIZE_T size) {
    if (size < 10) return false;
    for (SIZE_T i = 0; i < size - 10; i += 2) {
        if (data[i] == 'C' && data[i + 2] == ':' && data[i + 4] == '\\')
            return true;
    }
    return false;
}

double CalculateEntropy(const BYTE* data, SIZE_T size) {
    if (size == 0) return 0.0;
    int counts[256] = { 0 };
    for (SIZE_T i = 0; i < size; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

std::string ClassifyBuffer(const BYTE* buffer, SIZE_T size) {
    if (size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') return "PE";
    if (IsAsciiPrintable(buffer, size) && strstr((const char*)buffer, ".dll") && strstr((const char*)buffer, ":\\")) return "DLLPath";
    if (IsAsciiPrintable(buffer, size) && strstr((const char*)buffer, ".exe") && strstr((const char*)buffer, ":\\")) return "EXEPath";
    if (IsUnicodePath(buffer, size)) return "UnicodePath";
    if (CalculateEntropy(buffer, size) > 7.5) return "Encrypted";
    return "Shellcode";
}

void DumpBuffer(const char* prefix, const BYTE* buffer, SIZE_T size, const std::string& type) {
    char filename[MAX_PATH];
    sprintf_s(filename, "%s_%s_%llu.bin", prefix, type.c_str(), GetTickCount64());
    FILE* f = nullptr;
    fopen_s(&f, filename, "wb");
    if (f) {
        fwrite(buffer, 1, size, f);
        fclose(f);
        LogEvent("Dumped buffer to: " + std::string(filename));
    }
    else {
        LogEvent("Failed to dump buffer: " + std::string(filename));
    }
}

void SuspendTargetProcess(HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    LogEvent("Suspending process with PID: " + std::to_string(pid));
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
    LogEvent("Suspended process " + std::to_string(pid));
}

BOOL WINAPI Hooked_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    LogEvent("Hooked_WriteProcessMemory called");
    BYTE* localCopy = new BYTE[nSize];
    memcpy(localCopy, lpBuffer, nSize);

    std::string type = ClassifyBuffer(localCopy, nSize);
    LogEvent("Classified buffer as: " + type);

    DumpBuffer("WriteMem", localCopy, nSize, type);

    if (type == "PE" || type == "Shellcode" || type == "Encrypted" || type == "DLLPath" || type == "EXEPath" || type == "UnicodePath") {
        SuspendTargetProcess(hProcess);
    }

    delete[] localCopy;
    return Original_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI Hooked_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    LogEvent("Hooked_VirtualProtectEx called");
    return Original_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID WINAPI Hooked_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LogEvent("Hooked_VirtualAllocEx called");
    return Original_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

HANDLE WINAPI Hooked_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id) {
    LogEvent("Hooked_CreateRemoteThread called");
    SuspendTargetProcess(hProcess);
    return Original_CreateRemoteThread(hProcess, a, s, start, param, flags, id);
}

NTSTATUS WINAPI Hooked_NtCreateThreadEx(PHANDLE threadHandle, ACCESS_MASK access, LPVOID attr, HANDLE process, LPTHREAD_START_ROUTINE start, LPVOID param, BOOL suspended, SIZE_T zeroBits, SIZE_T reserve, SIZE_T commit, LPVOID attrList) {
    LogEvent("Hooked_NtCreateThreadEx called");
    SuspendTargetProcess(process);
    return Original_NtCreateThreadEx(threadHandle, access, attr, process, start, param, suspended, zeroBits, reserve, commit, attrList);
}

ULONG WINAPI Hooked_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR data) {
    LogEvent("Hooked_QueueUserAPC called");
    SuspendTargetProcess(GetCurrentProcess());
    return Original_QueueUserAPC(pfnAPC, hThread, data);
}

HANDLE WINAPI Hooked_CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES attr, DWORD protect, DWORD high, DWORD low, LPCSTR name) {
    LogEvent("Hooked_CreateFileMappingA called");
    return Original_CreateFileMappingA(hFile, attr, protect, high, low, name);
}

LPVOID WINAPI Hooked_MapViewOfFile(HANDLE mapping, DWORD access, DWORD high, DWORD low, SIZE_T size) {
    LogEvent("Hooked_MapViewOfFile called");
    return Original_MapViewOfFile(mapping, access, high, low, size);
}

void SetupHooks() {
    MH_Initialize();
    MH_CreateHook(&WriteProcessMemory, &Hooked_WriteProcessMemory, (LPVOID*)&Original_WriteProcessMemory);
    MH_CreateHook(&VirtualAllocEx, &Hooked_VirtualAllocEx, (LPVOID*)&Original_VirtualAllocEx);
    MH_CreateHook(&VirtualProtectEx, &Hooked_VirtualProtectEx, (LPVOID*)&Original_VirtualProtectEx);
    MH_CreateHook(&CreateRemoteThread, &Hooked_CreateRemoteThread, (LPVOID*)&Original_CreateRemoteThread);
    MH_CreateHookApi(L"ntdll.dll", "NtCreateThreadEx", &Hooked_NtCreateThreadEx, (LPVOID*)&Original_NtCreateThreadEx);
    MH_CreateHook(&CreateFileMappingA, &Hooked_CreateFileMappingA, (LPVOID*)&Original_CreateFileMappingA);
    MH_CreateHook(&MapViewOfFile, &Hooked_MapViewOfFile, (LPVOID*)&Original_MapViewOfFile);
    MH_CreateHook(&QueueUserAPC, &Hooked_QueueUserAPC, (LPVOID*)&Original_QueueUserAPC);
    MH_EnableHook(MH_ALL_HOOKS);
    LogEvent("All hooks installed.");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        SetupHooks();
    }
    return TRUE;
}

