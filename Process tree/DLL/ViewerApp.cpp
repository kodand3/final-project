#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <ctime>
#include <io.h>
#include <fcntl.h>
#include <algorithm>

#define MAX_PROCS 4096

struct ProcInfo {
    DWORD pid;
    DWORD ppid;
    char name[MAX_PATH];
    FILETIME creationTime;
};

ProcInfo* LoadMap() {
    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, "ProcMap");
    if (!hMap) {
        std::cerr << "[ViewerApp] Shared memory 'ProcMap' not found.\n";
        exit(1);
    }
    ProcInfo* procs = (ProcInfo*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!procs) {
        std::cerr << "[ViewerApp] Failed to map shared memory view.\n";
        exit(1);
    }
    return procs;
}

std::string FormatTime(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[100];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

void PrintTree(DWORD rootPID,
    const std::map<DWORD, std::vector<DWORD>>& tree,
    const std::map<DWORD, ProcInfo>& info,
    std::wstring prefix = L"", bool last = true) {

    auto it = info.find(rootPID);
    if (it == info.end()) return;

    std::wcout << prefix << (last ? L"└── " : L"├── ");
    std::wcout << it->second.name << L" (PID: " << rootPID
        << L", Created: " << FormatTime(it->second.creationTime).c_str() << L")\n";

    prefix += (last ? L"    " : L"│   ");

    auto childrenIt = tree.find(rootPID);
    if (childrenIt != tree.end()) {
        std::vector<DWORD> children = childrenIt->second;
        std::sort(children.begin(), children.end());  
        for (size_t i = 0; i < children.size(); ++i) {
            PrintTree(children[i], tree, info, prefix, i == children.size() - 1);
        }
    }
}

int main() {
    // Enable UTF-8 output
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);

    ProcInfo* procs = LoadMap();
    std::map<DWORD, std::vector<DWORD>> tree;
    std::map<DWORD, ProcInfo> info;
    std::set<std::pair<DWORD, DWORD>> seen_links;

    for (int i = 0; i < MAX_PROCS; ++i) {
        DWORD pid = procs[i].pid;
        DWORD ppid = procs[i].ppid;

        if (pid == 0) continue;

        // Save process info if not already known
        if (info.find(pid) == info.end())
            info[pid] = procs[i];

        // Avoid duplicate child entries
        if (seen_links.insert({ ppid, pid }).second) {
            tree[ppid].push_back(pid);
        }
    }

    std::wcout << L"[ViewerApp] Loaded " << info.size() << L" processes from shared memory.\n";

    // Print all raw process info
    std::wcout << L"\n[All Tracked Processes]\n";
    for (const auto& [pid, pi] : info) {
        std::wcout << L"PID: " << pi.pid
            << L", PPID: " << pi.ppid
            << L", Name: " << pi.name
            << L", Created: " << FormatTime(pi.creationTime).c_str() << L"\n";
    }

    while (true) {
        DWORD pid;
        std::wcout << L"\nEnter Parent PID (0 to exit): ";
        std::wcin >> pid;
        if (pid == 0) break;

        if (info.find(pid) == info.end()) {
            std::wcerr << L"[ViewerApp] PID " << pid << L" not found in memory.\n";
            continue;
        }

        std::wcout << L"\nProcess Tree:\n.\n";
        PrintTree(pid, tree, info);
    }

    return 0;
}
