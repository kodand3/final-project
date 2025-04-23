#include <ntddk.h>

#define DEVICE_NAME     L"\\Device\\apasyamkirikiri"
#define SYMLINK_NAME    L"\\DosDevices\\apasyamkirikiri"
#define IOCTL_GET_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

typedef struct _PROC_NODE {
    HANDLE Pid;
    HANDLE ParentPid;
    UNICODE_STRING ImagePath;
    LARGE_INTEGER CreateTime;
    LIST_ENTRY ListEntry;
} PROC_NODE, * PPROC_NODE;

LIST_ENTRY g_ProcessList;
KSPIN_LOCK g_ListLock;

VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status;
    int i;

    // Initialize Unicode strings using RtlInitUnicodeString
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    // Initialize our global list and spin lock
    InitializeListHead(&g_ProcessList);
    KeInitializeSpinLock(&g_ListLock);

    status = IoCreateDevice(DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Create the symbolic link for user-mode applications to open the device
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Set all major function pointers to our dispatch routine
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = DispatchDeviceControl;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Register process notify routine
    status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;

    // Initialize the symbolic link string for deletion
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    // Unregister process notifications
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

    // Delete symbolic link and device
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    // Clean up the process list
    KIRQL irql;
    KeAcquireSpinLock(&g_ListLock, &irql);

    while (!IsListEmpty(&g_ProcessList))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_ProcessList);
        PPROC_NODE node = CONTAINING_RECORD(entry, PROC_NODE, ListEntry);
        if (node->ImagePath.Buffer)
        {
            ExFreePoolWithTag(node->ImagePath.Buffer, 'pmim');
        }
        ExFreePoolWithTag(node, 'pmnd');
    }

    KeReleaseSpinLock(&g_ListLock, irql);
}

VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL)
    {
        return;
    }

    PPROC_NODE node = (PPROC_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROC_NODE), 'pmnd');
    if (!node)
    {
        return;
    }

    RtlZeroMemory(node, sizeof(PROC_NODE));
    node->Pid = ProcessId;
    node->ParentPid = CreateInfo->ParentProcessId;
    KeQuerySystemTime(&node->CreateTime);

    if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Length > 0)
    {
        node->ImagePath.Length = CreateInfo->ImageFileName->Length;
        node->ImagePath.MaximumLength = CreateInfo->ImageFileName->Length + sizeof(WCHAR);
        node->ImagePath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, node->ImagePath.MaximumLength, 'pmim');

        if (node->ImagePath.Buffer)
        {
            RtlZeroMemory(node->ImagePath.Buffer, node->ImagePath.MaximumLength);
            RtlCopyUnicodeString(&node->ImagePath, CreateInfo->ImageFileName);
        }
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_ListLock, &irql);
    InsertTailList(&g_ProcessList, &node->ListEntry);
    KeReleaseSpinLock(&g_ListLock, irql);
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_PROCESSES)
    {
        KIRQL irql;
        PLIST_ENTRY p;
        ULONG count = 0;
        ULONG needed;
        ULONG i = 0;

        KeAcquireSpinLock(&g_ListLock, &irql);

        for (p = g_ProcessList.Flink; p != &g_ProcessList; p = p->Flink)
        {
            count++;
        }

        needed = count * sizeof(PROC_NODE);
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < needed)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            info = needed;
        }
        else
        {
            PPROC_NODE out = (PPROC_NODE)Irp->AssociatedIrp.SystemBuffer;
            p = g_ProcessList.Flink;

            while (p != &g_ProcessList && i < count)
            {
                PPROC_NODE node = CONTAINING_RECORD(p, PROC_NODE, ListEntry);
                RtlCopyMemory(&out[i], node, sizeof(PROC_NODE));
                i++;
                p = p->Flink;
            }
            info = count * sizeof(PROC_NODE);
        }

        KeReleaseSpinLock(&g_ListLock, irql);
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

