# High-Recall Heuristics for Windows Malware Detection

## Introduction

Building a **high-recall malware pre-filter** means erring on the side of catching anything suspicious, even at the cost of false positives. Windows malware often leaves tell-tale signs in process behavior, file attributes, command usage, and system modifications. Below is a breakdown of suspicious indicators – from odd process patterns and parent-child relations to network and persistence signs – along with guidance on weighting these signals for a recall-biased scoring system. The aim is to recognize as many potential threats as possible by flagging malware;

## Implementation Plan

![project-1](https://github.com/user-attachments/assets/05ed2475-b309-49bc-965e-5ab3d601451d)


---

## **Step 1: Collect Process Info

For each **new process** that starts, collect these **small**, **fast** details:

| Info                            | How to Get It                                                   |
| :------------------------------ | :-------------------------------------------------------------- |
| Parent process name and PID     | `CreateToolhelp32Snapshot` + `Process32First` / `Process32Next` |
| Executable path                 | `GetModuleFileNameEx`                                           |
| Command line args               | `QueryFullProcessImageName` / `GetCommandLine`                  |
| Is executable signed?           | Check file signature via `WinVerifyTrust`                       |
| File creation time              | `GetFileTime`                                                   |
| Entropy (optional for binaries) | Read `.text` section and calculate entropy                      |
| Network activity?               | ETW lightweight event (optional)                                |
| Registry modifications?         | Monitor for Run keys via ETW (optional)                         |
| Child process count?            | Count over time (spawn many children = suspicious)              |

**Tools to use:**
- Native APIs (faster, more control) ----> `CreateToolhelp32Snapshot`, `OpenProcess`, etc.
- Event Tracing for Windows ---> high performance later(Implementation later)

---

## **Step 2: Suspicion Rules**

When a **new process** spawns:
Check it against the **heuristic table**:  

|Category|Feature|Description|
|---|---|---|
|**Execution Context**|Parent Process|Flag if child of `cmd.exe`, `powershell.exe`, `wscript.exe`, etc.|
||Process Path|Flag if running from `%AppData%`, `%TEMP%`, Downloads, etc.|
||Executable Name|Flag known spoofed names (`svchost.exe` in wrong path)|
||Creation Time|Flag if created within last 1–2 mins|
||Command Line|Flag for suspicious args (`-enc`, `-nop`, `bypass`, URLs)|
|**Binary Info**|Signature Validity|Flag unsigned or self-signed binaries|
||File Entropy|Flag high entropy (suggests packing)|
||PE Size|Flag very small binaries (<20KB)|
|**Behavior**|Network Activity|Flags if opens a socket shortly after starting|
||Writes to Disk|Flags if writing executables to temp folders|
||Injects Memory|Flags if opening handles to another process|
||Starts Many Procs|Flags if spawning many children in short time|


|Rule|Score|
|---|---|
|Suspicious parent (e.g., `powershell.exe`)|+20|
|Executable running from `%TEMP%` or `%AppData%`|+20|
|Unsigned binary|+15|
|Suspicious command-line args|+25|
|File entropy > 7.0|+15|
|Process spawned within last 60 seconds|+10|
|Executable name spoofing|+20|
|Network connection within 30s of start|+20|
|Accessing memory of another process|+30|
|Writing .exe to disk|+20|
|Rapid child process spawning (>3 in 10s)|+15|

Each rule it matches → **add the corresponding suspicion score**.

#### **Note**: Needs rigorous testing. Values are not perfect.

---

## **Step 3: Compare to Threshold**

If **Suspicion Score ≥ Threshold**  
	Send to Full Analyzer
Else 
	**Ignore** (do not analyze).

---

## **Step 4: Maintain a Small Cache**

We are going to make small in-memory table:

| PID | Process Name | Suspicion Score | Analyzed (Y/N) |
| :-- | :----------- | :-------------- | :------------- |

- So we **don't reprocess** same process again and again.
- Expire entries when the process exits (listen for exit events).

---

## **Optimizations**

- **We do not store full process dumps** unless flagged.
- Let us only store a few hundred bytes per process (names, scores, basic flags).
- Clean up cache every few minutes or on process termination

This way we stay **extremely lightweight**.

---

## Rough Pseudocode

```cpp
OnNewProcess(Process):
    info = CollectBasicInfo(Process)
    score = 0
    threshold = __YET_TO_BE_CALCULATED__

    if info.parent in ["powershell.exe", "wscript.exe", "cmd.exe"]:
        score += 20
    if info.path contains "AppData" or "Temp":
        score += 20
    if info.signature == "unsigned":
        score += 15
    if info.cmdline contains "-enc" or "downloadstring":
        score += 25
    if info.executable_entropy > 7.0:
        score += 15
    if info.created_within_last_minute:
        score += 10
    if info.network_activity_in_10s:
        score += 20
    // more rules

    if score >= threshold:
        SendToFullAnalyzer(Process)
    else:
        SkipAnalysis(Process)

    CacheProcessInfo(Process, score)
```

---


## Code

#### Structure
|File|Purpose|
|---|---|
|`main.cpp`|Start system|
|`ProcessMonitor.h/.cpp`|Process event detection|
|`SuspicionScorer.h/.cpp`|Apply scoring rules|
|`ProcessCache.h/.cpp`|Store and manage process info|
|`AnalyzerDispatcher.h/.cpp`|Dispatch suspicious processes|
|`Utils.h/.cpp`|Helper functions|
|`Config.h`|Config values|


- config.h
```cpp
#pragma once

namespace Config {
    constexpr int SuspicionThreshold = 40;

    // Rule Weights
    constexpr int SuspiciousParentWeight = 20;
    constexpr int TempPathWeight = 20;
    constexpr int UnsignedBinaryWeight = 15;
    constexpr int EncodedCommandWeight = 25;
    constexpr double HighEntropyThreshold = 7.0;
}
```


- utils.h
```cpp
#pragma once
#include <string>

namespace Utils {
    bool IsUnsignedBinary(const std::wstring& path);
    double CalculateEntropy(const std::wstring& path);
}

```


- utils.cpp
```cpp
#include "Utils.h"
#include <windows.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <wintrust.h>
#include <fstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

bool Utils::IsUnsignedBinary(const std::wstring& path) {
    LONG lStatus;
    WINTRUST_FILE_INFO fileInfo = { 0 };
    WINTRUST_DATA winTrustData = { 0 };

    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

    // Clean up
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

    return lStatus != ERROR_SUCCESS;
}

double Utils::CalculateEntropy(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0.0;

    unsigned char buffer[4096];
    size_t counts[256] = { 0 };
    size_t total = 0;

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || file.gcount()) {
        size_t n = file.gcount();
        for (size_t i = 0; i < n; ++i) {
            counts[buffer[i]]++;
        }
        total += n;
    }
    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

```


- processcache.cpp
```cpp
#pragma once
#include <unordered_map>
#include <string>

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    int suspicionScore;
    bool analyzed;
    std::wstring path;
};

class ProcessCache {
public:
    void AddOrUpdateProcess(const ProcessInfo& info);
    bool IsAlreadyAnalyzed(DWORD pid);
    ProcessInfo* GetProcess(DWORD pid);
    void CleanupExitedProcesses();
private:
    std::unordered_map<DWORD, ProcessInfo> processMap;
};

```


- processcache.cpp
```cpp
#include "ProcessCache.h"
#include <windows.h>

void ProcessCache::AddOrUpdateProcess(const ProcessInfo& info) {
    processMap[info.pid] = info;
}

bool ProcessCache::IsAlreadyAnalyzed(DWORD pid) {
    auto it = processMap.find(pid);
    return (it != processMap.end() && it->second.analyzed);
}

ProcessInfo* ProcessCache::GetProcess(DWORD pid) {
    auto it = processMap.find(pid);
    if (it != processMap.end())
        return &it->second;
    return nullptr;
}

void ProcessCache::CleanupExitedProcesses() {
    for (auto it = processMap.begin(); it != processMap.end(); ) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, it->first);
        if (!hProcess || WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
            it = processMap.erase(it);
        } else {
            ++it;
        }
        if (hProcess) CloseHandle(hProcess);
    }
}

```


- SuspicionScorer.h

```cpp
#pragma once
#include "ProcessCache.h"

class SuspicionScorer {
public:
    int ScoreProcess(ProcessInfo& info);
};

```

- SuspicionScorer.cpp
```cpp
#include "SuspicionScorer.h"
#include "Config.h"
#include "Utils.h"
#include <windows.h>

int SuspicionScorer::ScoreProcess(ProcessInfo& info) {
    int score = 0;

    if (info.name == L"powershell.exe" || info.name == L"cmd.exe" || info.name == L"wscript.exe")
        score += Config::SuspiciousParentWeight;

    if (info.path.find(L"AppData") != std::wstring::npos || info.path.find(L"Temp") != std::wstring::npos)
        score += Config::TempPathWeight;

    if (Utils::IsUnsignedBinary(info.path))
        score += Config::UnsignedBinaryWeight;

    double entropy = Utils::CalculateEntropy(info.path);
    if (entropy > Config::HighEntropyThreshold)
        score += 15; // Add some weight for high entropy

    return score;
}

```


- `AnalyzerDispatcher`.h

```cpp
#pragma once
#include "ProcessCache.h"

class AnalyzerDispatcher {
public:
    void AnalyzeProcess(const ProcessInfo& info);
};

```

- `AnalyzerDispatcher`.cpp
```cpp
#include "AnalyzerDispatcher.h"
#include <iostream>

void AnalyzerDispatcher::AnalyzeProcess(const ProcessInfo& info) {
    std::wcout << L"[Analyzer] Analyzing Process: " << info.name 
               << L" (PID " << info.pid << L") Path: " << info.path << L"\n";
    // Wokk TODO: Hook into your heavy API call analyzer system
    // Waiting for model from saurav
}

```



- processmonitor.h
```cpp
#pragma once
#include "ProcessCache.h"
#include "SuspicionScorer.h"
#include "AnalyzerDispatcher.h"

class ProcessMonitor {
public:
    ProcessMonitor();
    void Monitor();
private:
    ProcessCache cache;
    SuspicionScorer scorer;
    AnalyzerDispatcher dispatcher;
};

```


- processmonitor.cpp
```cpp
#include "ProcessMonitor.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

ProcessMonitor::ProcessMonitor() {}

void ProcessMonitor::Monitor() {
    while (true) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe)) {
            do {
                if (!cache.IsAlreadyAnalyzed(pe.th32ProcessID)) {
                    ProcessInfo info;
                    info.pid = pe.th32ProcessID;
                    info.name = pe.szExeFile;
                    info.analyzed = false;

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        wchar_t path[MAX_PATH] = { 0 };
                        DWORD size = MAX_PATH;
                        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                            info.path = path;
                        }
                        CloseHandle(hProcess);
                    }

                    int score = scorer.ScoreProcess(info);
                    info.suspicionScore = score;
                    cache.AddOrUpdateProcess(info);

                    if (score >= Config::SuspicionThreshold) {
                        dispatcher.AnalyzeProcess(info);
                        cache.GetProcess(pe.th32ProcessID)->analyzed = true;
                    }
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);

        cache.CleanupExitedProcesses();
        Sleep(5000); // Poll every 5 seconds
    }
}

```


- main.cpp
```cpp
#include "ProcessMonitor.h"

int main() {
    ProcessMonitor monitor;
    monitor.Monitor();
    return 0;
}

```


### Upgrades that can done

- Instead of polling have live monitor
- Maybe better parent-child relationship tracker ---> Try using the driver made(refer github processtree part)
