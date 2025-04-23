#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <ctime>

#define IOCTL_GET_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

struct PROC_NODE {
    DWORD_PTR Pid;
    DWORD_PTR ParentPid;
    WCHAR ImagePath[260];
    LARGE_INTEGER CreateTime;
};

std::unordered_map<DWORD_PTR, std::vector<PROC_NODE>> procTree;
std::unordered_map<DWORD_PTR, PROC_NODE> procLookup;

std::wstring FormatTime(const LARGE_INTEGER& fileTime) {
    FILETIME ft;
    ft.dwLowDateTime = fileTime.LowPart;
    ft.dwHighDateTime = fileTime.HighPart;

    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    wchar_t buffer[100];
    swprintf(buffer, 100, L"%04d-%02d-%02d %02d:%02d:%02d",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    return buffer;
}

void PrintTree(DWORD_PTR pid, const std::wstring& prefix = L"", bool isLast = true) {
    if (procLookup.find(pid) == procLookup.end()) return;

    const PROC_NODE& node = procLookup[pid];

    std::wcout << prefix;
    std::wcout << (isLast ? L"└── " : L"├── ");
    std::wcout << node.ImagePath << L" (PID " << node.Pid << L") [" << FormatTime(node.CreateTime) << L"]\n";

    const std::vector<PROC_NODE>& children = procTree[pid];
    for (size_t i = 0; i < children.size(); ++i) {
        bool last = (i == children.size() - 1);
        std::wstring childPrefix = prefix + (isLast ? L"    " : L"│   ");
        PrintTree(children[i].Pid, childPrefix, last);
    }
}

int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\ProcMonDev", GENERIC_READ,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device." << std::endl;
        return 1;
    }

    DWORD outSize = 100000;
    std::vector<BYTE> buffer(outSize);
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDevice, IOCTL_GET_PROCESSES, NULL, 0,
        buffer.data(), outSize, &bytesReturned, NULL)) {
        std::cerr << "DeviceIoControl failed." << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    size_t count = bytesReturned / sizeof(PROC_NODE);
    PROC_NODE* list = (PROC_NODE*)buffer.data();

    for (size_t i = 0; i < count; i++) {
        procTree[list[i].ParentPid].push_back(list[i]);
        procLookup[list[i].Pid] = list[i];
    }

    std::wcout << L"Enter PID to print process tree: ";
    DWORD_PTR inputPid;
    std::wcin >> inputPid;

    if (procLookup.find(inputPid) == procLookup.end()) {
        std::wcout << L"PID not found.\n";
    }
    else {
        std::wcout << L"\nProcess Tree:\n";
        std::wcout << L".\n";
        PrintTree(inputPid);
    }

    CloseHandle(hDevice);
    return 0;
}

