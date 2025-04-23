#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <stdlib.h>     // for wcstombs_s
#include "MinHook.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(NTAPI* NtCreateUserProcess_t)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PVOID ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList
    );

NtCreateUserProcess_t Original_NtCreateUserProcess = nullptr;

#define MAX_PROCS 4096

struct ProcInfo {
    DWORD pid;
    DWORD ppid;
    char name[MAX_PATH];
    FILETIME creationTime;
};

static ProcInfo* g_procMap = nullptr;
static HANDLE g_mutex = nullptr;

void SaveProcessInfo(DWORD parentPID, DWORD childPID) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    while (Process32NextW(hSnap, &pe)) {
        if (pe.th32ProcessID == childPID) {
            WaitForSingleObject(g_mutex, INFINITE);

            for (int i = 0; i < MAX_PROCS; ++i) {
                if (g_procMap[i].pid == 0) {
                    g_procMap[i].pid = childPID;
                    g_procMap[i].ppid = parentPID;

                    size_t converted = 0;
                    wcstombs_s(&converted, g_procMap[i].name, MAX_PATH, pe.szExeFile, _TRUNCATE);

                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, childPID);
                    if (hProc) {
                        FILETIME ft[4];
                        if (GetProcessTimes(hProc, &ft[0], &ft[1], &ft[2], &ft[3])) {
                            g_procMap[i].creationTime = ft[0];
                        }
                        CloseHandle(hProc);
                    }
                    break;
                }
            }

            ReleaseMutex(g_mutex);
            break;
        }
    }

    CloseHandle(hSnap);
}

NTSTATUS NTAPI Hooked_NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PVOID ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList)
{
    DWORD parentPID = GetCurrentProcessId();

    NTSTATUS status = Original_NtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList
    );

    if (NT_SUCCESS(status) && ProcessHandle && *ProcessHandle) {
        DWORD childPID = GetProcessId(*ProcessHandle);
        SaveProcessInfo(parentPID, childPID);
    }

    return status;
}

void LogSelfProcess() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    while (Process32NextW(hSnap, &pe)) {
        if (pe.th32ProcessID == pid) {
            WaitForSingleObject(g_mutex, INFINITE);

            for (int i = 0; i < MAX_PROCS; ++i) {
                if (g_procMap[i].pid == 0) {
                    g_procMap[i].pid = pid;
                    g_procMap[i].ppid = pe.th32ParentProcessID;

                    size_t converted = 0;
                    wcstombs_s(&converted, g_procMap[i].name, MAX_PATH, pe.szExeFile, _TRUNCATE);

                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if (hProc) {
                        FILETIME ft[4];
                        if (GetProcessTimes(hProc, &ft[0], &ft[1], &ft[2], &ft[3])) {
                            g_procMap[i].creationTime = ft[0];
                        }
                        CloseHandle(hProc);
                    }
                    break;
                }
            }

            ReleaseMutex(g_mutex);
            break;
        }
    }

    CloseHandle(hSnap);
}

DWORD WINAPI InitHook(LPVOID) {
    if (MH_Initialize() != MH_OK)
        return 1;

    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;

    auto target = GetProcAddress(ntdll, "NtCreateUserProcess");
    if (!target) return 1;

    if (MH_CreateHook(target, Hooked_NtCreateUserProcess, reinterpret_cast<LPVOID*>(&Original_NtCreateUserProcess)) != MH_OK)
        return 1;

    if (MH_EnableHook(target) != MH_OK)
        return 1;

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ProcInfo) * MAX_PROCS, "ProcMap");
        g_procMap = (ProcInfo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        g_mutex = CreateMutexA(NULL, FALSE, "ProcMapMutex");

        // Log the current process
        LogSelfProcess();

        // Start hook setup
        CreateThread(0, 0, InitHook, 0, 0, 0);
    }
    return TRUE;
}

