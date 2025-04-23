#include <windows.h>
#include <iostream>

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

// Function prototypes
void ServiceMain(DWORD argc, LPTSTR* argv);
void ControlHandler(DWORD request);
void RunServiceLogic();

int wmain() {  // Change to wmain() to support wide strings
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"SimpleService", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}

void ServiceMain(DWORD argc, LPTSTR* argv) {
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    hStatus = RegisterServiceCtrlHandlerW(L"SimpleService", (LPHANDLER_FUNCTION)ControlHandler);
    SetServiceStatus(hStatus, &ServiceStatus);

    RunServiceLogic();
}

void ControlHandler(DWORD request) {
    if (request == SERVICE_CONTROL_STOP) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
    }
}

void RunServiceLogic() {
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        HANDLE hHeap = GetProcessHeap();
        void* pMemory = HeapAlloc(hHeap, 0, 512);  // Allocate 512 bytes

        if (pMemory) {
            std::wcout << L"[Service] HeapAlloc called!\n";  // Use wide string output
            HeapFree(hHeap, 0, pMemory);
        }

        Sleep(5000);  // Run every 5 seconds
    }
}

