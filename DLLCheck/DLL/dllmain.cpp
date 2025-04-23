// ========== PREPROCESSOR DIRECTIVES ==========
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <wincrypt.h>
#include <softpub.h>
#include <iostream>
#include <fstream>
#include <string>
#include "MinHook.h"

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif


// ========== LIBRARIES ==========
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "minhook.lib")

// ========== CONSTANTS ==========
const char* avMarker = "AVHOOK_MARKER_SECURITY";

// ========== FUNCTION POINTERS ==========
typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR);
typedef HMODULE(WINAPI* LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);

LoadLibraryA_t fpLoadLibraryA = nullptr;
LoadLibraryW_t fpLoadLibraryW = nullptr;
LoadLibraryExA_t fpLoadLibraryExA = nullptr;
LoadLibraryExW_t fpLoadLibraryExW = nullptr;
LdrLoadDll_t fpLdrLoadDll = nullptr;

// ========== FUNCTION DEFINITIONS ==========

// Checks if the DLL has the AV marker
bool HasAVMarker(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return content.find(avMarker) != std::string::npos;
}

// Checks if a DLL is signed
bool IsSignatureValid(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (status == ERROR_SUCCESS);
}

// Validates the DLL file based on marker or signature
bool ValidateDll(const std::wstring& filePath) {
    if (HasAVMarker(filePath)) {
        std::wcout << L"[+] Whitelisted AV DLL: " << filePath << std::endl;
        return true;
    }

    if (IsSignatureValid(filePath)) {
        std::wcout << L"[+] Signed DLL allowed: " << filePath << std::endl;
        return true;
    }

    std::wcerr << L"[!] Blocked suspicious DLL: " << filePath << std::endl;
    return false;
}

// Hooked LoadLibraryA
HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
    std::wstring filePath(lpLibFileName, lpLibFileName + strlen(lpLibFileName));
    if (ValidateDll(filePath)) {
        return fpLoadLibraryA(lpLibFileName);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

// Hooked LoadLibraryW
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
    std::wstring filePath(lpLibFileName);
    if (ValidateDll(filePath)) {
        return fpLoadLibraryW(lpLibFileName);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

// Hooked LoadLibraryExA
HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    std::wstring filePath(lpLibFileName, lpLibFileName + strlen(lpLibFileName));
    if (ValidateDll(filePath)) {
        return fpLoadLibraryExA(lpLibFileName, hFile, dwFlags);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

// Hooked LoadLibraryExW
HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    std::wstring filePath(lpLibFileName);
    if (ValidateDll(filePath)) {
        return fpLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

// Hooked LdrLoadDll
NTSTATUS NTAPI HookedLdrLoadDll(PWSTR SearchPath, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle) {
    if (ModuleFileName && ModuleFileName->Buffer) {
        std::wstring filePath(ModuleFileName->Buffer);
        if (ValidateDll(filePath)) {
            return fpLdrLoadDll(SearchPath, Flags, ModuleFileName, ModuleHandle);
        }
        return STATUS_ACCESS_DENIED;
    }
    return fpLdrLoadDll(SearchPath, Flags, ModuleFileName, ModuleHandle);
}

// Initializes all hooks
void InitializeHooks() {
    if (MH_Initialize() != MH_OK) {
        std::cerr << "[!] Failed to initialize MinHook.\n";
        return;
    }

    MH_CreateHook(&LoadLibraryA, &HookedLoadLibraryA, (LPVOID*)&fpLoadLibraryA);
    MH_EnableHook(&LoadLibraryA);

    MH_CreateHook(&LoadLibraryW, &HookedLoadLibraryW, (LPVOID*)&fpLoadLibraryW);
    MH_EnableHook(&LoadLibraryW);

    MH_CreateHook(&LoadLibraryExA, &HookedLoadLibraryExA, (LPVOID*)&fpLoadLibraryExA);
    MH_EnableHook(&LoadLibraryExA);

    MH_CreateHook(&LoadLibraryExW, &HookedLoadLibraryExW, (LPVOID*)&fpLoadLibraryExW);
    MH_EnableHook(&LoadLibraryExW);

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        fpLdrLoadDll = (LdrLoadDll_t)GetProcAddress(hNtdll, "LdrLoadDll");
        if (fpLdrLoadDll) {
            MH_CreateHook(fpLdrLoadDll, &HookedLdrLoadDll, (LPVOID*)&fpLdrLoadDll);
            MH_EnableHook(fpLdrLoadDll);
        }
    }

    std::cout << "[+] All hooks initialized.\n";
}

// Entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeHooks();
    }
    return TRUE;
}

