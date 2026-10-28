// ============================================================================
// IoControl.cpp - IOCTL处理实现
// ============================================================================

#include "IoControl.hpp"
#include "DataManager.hpp"
#include "UserHookMgr.hpp"
#include "SyscallHook.hpp"
#include "Utils.hpp"
#include <ntstrsafe.h>

// ============================================================================
// 默认分发函数
// ============================================================================

NTSTATUS IoControl_DispatchDefault(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// Create分发函数
// ============================================================================

NTSTATUS IoControl_DispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    ULONG openPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    DBG_PRINT("IoControl_DispatchCreate: Device opened by PID %lu\n", openPid);

    // 检查是否为受监控进程——若是，说明 DllMain 已成功执行并到达 DriverComm_Initialize
    PPROCESS_NODE monNode = DataManager_FindProcess((HANDLE)(ULONG_PTR)openPid);
    if (monNode) {
        ExAcquirePushLockExclusive(&monNode->NodeLock);
        monNode->DllConnected = TRUE;
        ExReleasePushLockExclusive(&monNode->NodeLock);
        DataManager_ReleaseProcess(monNode);
        DBG_PRINT("IoControl_DispatchCreate: *** PID %lu DLL已连接 — DllMain执行成功 ***\n",
            openPid);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// ============================================================================
// Close分发函数
// ============================================================================

NTSTATUS IoControl_DispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DBG_PRINT("IoControl_DispatchClose: Device closed by PID %lu\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// ============================================================================
// Read分发函数 (用于读取日志)
// ============================================================================

NTSTATUS IoControl_DispatchRead(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG readLength = irpStack->Parameters.Read.Length;
    ULONG bytesRead = 0;

    if (readLength == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    // 获取缓冲区地址
    PVOID buffer = NULL;

    if (Irp->MdlAddress) {
        buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    }
    else if (Irp->AssociatedIrp.SystemBuffer) {
        buffer = Irp->AssociatedIrp.SystemBuffer;
    }

    if (!buffer) {
        DBG_PRINT("IoControl_DispatchRead: Failed to get buffer address\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }

    // 计算可以读取的日志条目数
    ULONG maxEntries = readLength / sizeof(SHELLCODE_LOG_ENTRY);

    if (maxEntries == 0) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Complete;
    }

    // 读取日志
    ULONG entriesRead = DataManager_GetLogEntries(
        (PSHELLCODE_LOG_ENTRY)buffer,
        maxEntries
    );

    bytesRead = entriesRead * sizeof(SHELLCODE_LOG_ENTRY);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
    DBG_PRINT("IoControl_DispatchRead: Read %lu log entries (%lu bytes)\n",
        entriesRead, bytesRead);
#endif

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesRead;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// ============================================================================
// DeviceControl分发函数
// ============================================================================

NTSTATUS IoControl_DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // IOCTL 日志仅在 DEBUG_VERBOSE 下输出（高频、内部细节）
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
    DBG_PRINT("IoControl_DispatchDeviceControl: IOCTL=0x%08X, InLen=%lu, OutLen=%lu, PID=%lu\n",
        ioControlCode, inputLength, outputLength,
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
#endif

    switch (ioControlCode) {
    case IOCTL_EXCEPTION_REPORT:
        status = IoControl_HandleExceptionReport(
            inputBuffer,
            inputLength,
            outputBuffer,
            outputLength,
            &bytesReturned
        );
        break;

    case IOCTL_QUERY_MEMORY_INFO:
        status = IoControl_HandleQueryMemoryInfo(
            inputBuffer,
            inputLength,
            outputBuffer,
            outputLength,
            &bytesReturned
        );
        break;

    case IOCTL_GET_LOG_ENTRIES:
        status = IoControl_HandleGetLogEntries(
            outputBuffer,
            outputLength,
            &bytesReturned
        );
        break;

    case IOCTL_TEST_CONNECTION:
        status = IoControl_HandleTestConnection(
            outputBuffer,
            outputLength,
            &bytesReturned
        );
        break;

    case IOCTL_HIDE_MODULE:
        status = IoControl_HandleHideModule(
            inputBuffer,
            inputLength,
            &bytesReturned
        );
        break;

    default:
        DBG_PRINT("IoControl_DispatchDeviceControl: Unknown IOCTL 0x%08X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// ============================================================================
// 异常报告处理
// ============================================================================

NTSTATUS IoControl_HandleExceptionReport(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    *BytesReturned = 0;

    // 接受 64-bit DLL（112 字节）或 32-bit WoW64 DLL（72 字节）发来的缓冲区
    if (!InputBuffer || InputBufferLength < sizeof(EXCEPTION_REPORT_PACKET_32)) {
        DBG_PRINT("IoControl_HandleExceptionReport: Invalid input buffer (len=%lu, min=%lu)\n",
            InputBufferLength, (ULONG)sizeof(EXCEPTION_REPORT_PACKET_32));
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 接受 64-bit（32 字节）或 32-bit（20 字节）响应缓冲区
    if (!OutputBuffer || OutputBufferLength < sizeof(EXCEPTION_RESPONSE_PACKET_32)) {
        DBG_PRINT("IoControl_HandleExceptionReport: Invalid output buffer (len=%lu, min=%lu)\n",
            OutputBufferLength, (ULONG)sizeof(EXCEPTION_RESPONSE_PACKET_32));
        return STATUS_BUFFER_TOO_SMALL;
    }

    // METHOD_BUFFERED: InputBuffer 与 OutputBuffer 指向同一块 SystemBuffer。
    // 必须先将 Report 完整拷贝到局部变量，再写 Response，否则写入会覆盖输入数据。
    EXCEPTION_REPORT_PACKET reportCopy;
    RtlZeroMemory(&reportCopy, sizeof(reportCopy));

    if (InputBufferLength >= sizeof(EXCEPTION_REPORT_PACKET)) {
        // 64-bit DLL：直接拷贝
        RtlCopyMemory(&reportCopy, InputBuffer, sizeof(EXCEPTION_REPORT_PACKET));
    } else {
        // 32-bit WoW64 DLL：逐字段展开为 64-bit 结构
        PEXCEPTION_REPORT_PACKET_32 pkt32 = (PEXCEPTION_REPORT_PACKET_32)InputBuffer;
        reportCopy.ExceptionCode    = pkt32->ExceptionCode;
        reportCopy.ExceptionFlags   = pkt32->ExceptionFlags;
        reportCopy.ExceptionAddress = (ULONG_PTR)pkt32->ExceptionAddress;
        reportCopy.FaultAddress     = (ULONG_PTR)pkt32->FaultAddress;
        reportCopy.AccessType       = (ULONG_PTR)pkt32->AccessType;
        reportCopy.ProcessId        = pkt32->ProcessId;
        reportCopy.ThreadId         = pkt32->ThreadId;
        reportCopy.ContextRip       = (ULONG_PTR)pkt32->ContextEip;
        reportCopy.ContextRsp       = (ULONG_PTR)pkt32->ContextEsp;
        reportCopy.ContextRbp       = (ULONG_PTR)pkt32->ContextEbp;
        reportCopy.ContextFlags     = (ULONG_PTR)pkt32->ContextFlags;
        reportCopy.Timestamp        = pkt32->Timestamp;
    }

    // 验证报告内容
    if (reportCopy.ExceptionCode != STATUS_ACCESS_VIOLATION) {
        DBG_PRINT("IoControl_HandleExceptionReport: Not an access violation (0x%08X)\n",
            reportCopy.ExceptionCode);

        if (OutputBufferLength >= sizeof(EXCEPTION_RESPONSE_PACKET)) {
            PEXCEPTION_RESPONSE_PACKET resp = (PEXCEPTION_RESPONSE_PACKET)OutputBuffer;
            resp->Status = STATUS_INVALID_PARAMETER;
            resp->Action = EXCEPTION_ACTION_PASSTHROUGH;
            *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET);
        } else {
            PEXCEPTION_RESPONSE_PACKET_32 resp32 = (PEXCEPTION_RESPONSE_PACKET_32)OutputBuffer;
            resp32->Status = STATUS_INVALID_PARAMETER;
            resp32->Action = EXCEPTION_ACTION_PASSTHROUGH;
            resp32->NewProtection = 0;
            resp32->Reserved[0] = resp32->Reserved[1] = 0;
            *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET_32);
        }
        return STATUS_SUCCESS;
    }

    if (reportCopy.AccessType != 8) {  // 8 = Execute violation
        DBG_PRINT("IoControl_HandleExceptionReport: Not an execute violation (type=%llu)\n",
            reportCopy.AccessType);

        if (OutputBufferLength >= sizeof(EXCEPTION_RESPONSE_PACKET)) {
            PEXCEPTION_RESPONSE_PACKET resp = (PEXCEPTION_RESPONSE_PACKET)OutputBuffer;
            resp->Status = STATUS_INVALID_PARAMETER;
            resp->Action = EXCEPTION_ACTION_PASSTHROUGH;
            *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET);
        } else {
            PEXCEPTION_RESPONSE_PACKET_32 resp32 = (PEXCEPTION_RESPONSE_PACKET_32)OutputBuffer;
            resp32->Status = STATUS_INVALID_PARAMETER;
            resp32->Action = EXCEPTION_ACTION_PASSTHROUGH;
            resp32->NewProtection = 0;
            resp32->Reserved[0] = resp32->Reserved[1] = 0;
            *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET_32);
        }
        return STATUS_SUCCESS;
    }

    // 调用 UserHookMgr 处理异常（局部副本，不受 Response 写入影响）
    EXCEPTION_RESPONSE_PACKET respFull;
    RtlZeroMemory(&respFull, sizeof(respFull));
    NTSTATUS status = UserHookMgr_HandleException(&reportCopy, &respFull);

    // 将响应写入输出缓冲区（兼容 32-bit / 64-bit 两种大小）
    if (OutputBufferLength >= sizeof(EXCEPTION_RESPONSE_PACKET)) {
        RtlCopyMemory(OutputBuffer, &respFull, sizeof(EXCEPTION_RESPONSE_PACKET));
        *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET);
    } else {
        PEXCEPTION_RESPONSE_PACKET_32 resp32 = (PEXCEPTION_RESPONSE_PACKET_32)OutputBuffer;
        resp32->Status        = respFull.Status;
        resp32->Action        = respFull.Action;
        resp32->NewProtection = (ULONG)respFull.NewProtection;
        resp32->Reserved[0]   = resp32->Reserved[1] = 0;
        *BytesReturned = sizeof(EXCEPTION_RESPONSE_PACKET_32);
    }

    DBG_PRINT("IoControl_HandleExceptionReport: Handled exception, Action=%lu\n",
        respFull.Action);

    return status;
}

// ============================================================================
// 查询内存信息处理
// ============================================================================

// 查询请求结构
typedef struct _QUERY_MEMORY_REQUEST {
    HANDLE  ProcessId;
    PVOID   Address;
} QUERY_MEMORY_REQUEST, * PQUERY_MEMORY_REQUEST;

// 查询响应结构
typedef struct _QUERY_MEMORY_RESPONSE {
    BOOLEAN     Found;
    ULONG_PTR   BaseAddress;
    SIZE_T      RegionSize;
    ULONG       CurrentProtection;
    ULONG       OriginalProtection;
    HANDLE      InitiatorPid;
    BOOLEAN     IsDirty;
} QUERY_MEMORY_RESPONSE, * PQUERY_MEMORY_RESPONSE;

NTSTATUS IoControl_HandleQueryMemoryInfo(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    *BytesReturned = 0;

    if (!InputBuffer || InputBufferLength < sizeof(QUERY_MEMORY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!OutputBuffer || OutputBufferLength < sizeof(QUERY_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // METHOD_BUFFERED: Input/Output 共享 SystemBuffer，先复制 request 再写 response
    QUERY_MEMORY_REQUEST requestCopy;
    RtlCopyMemory(&requestCopy, InputBuffer, sizeof(QUERY_MEMORY_REQUEST));

    PQUERY_MEMORY_RESPONSE response = (PQUERY_MEMORY_RESPONSE)OutputBuffer;
    RtlZeroMemory(response, sizeof(QUERY_MEMORY_RESPONSE));

    // 查找内存区域快照，避免在释放 AVL 锁后继续使用节点裸指针
    MEMORY_REGION_NODE regionSnapshot = { 0 };
    if (DataManager_QueryMemoryRegionSnapshot(
        requestCopy.ProcessId,
        (ULONG_PTR)requestCopy.Address,
        &regionSnapshot))
    {
        response->Found = TRUE;
        response->BaseAddress = regionSnapshot.StartAddress;
        response->RegionSize = regionSnapshot.EndAddress - regionSnapshot.StartAddress;
        response->CurrentProtection = regionSnapshot.CurrentProtection;
        response->OriginalProtection = regionSnapshot.OriginalProtection;
        response->InitiatorPid = regionSnapshot.InitiatorPid;
        response->IsDirty = regionSnapshot.IsDirty;

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
        DBG_PRINT("IoControl_HandleQueryMemoryInfo: Found region [%p-%p) for PID %lu\n",
            (PVOID)response->BaseAddress,
            (PVOID)(response->BaseAddress + response->RegionSize),
            (ULONG)(ULONG_PTR)requestCopy.ProcessId);
#endif
    }
    else {
        response->Found = FALSE;

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
        DBG_PRINT("IoControl_HandleQueryMemoryInfo: Region not found for PID %lu, Address %p\n",
            (ULONG)(ULONG_PTR)requestCopy.ProcessId, requestCopy.Address);
#endif
    }

    *BytesReturned = sizeof(QUERY_MEMORY_RESPONSE);
    return STATUS_SUCCESS;
}

// ============================================================================
// 获取日志条目处理
// ============================================================================

NTSTATUS IoControl_HandleGetLogEntries(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    *BytesReturned = 0;

    if (!OutputBuffer || OutputBufferLength < sizeof(SHELLCODE_LOG_ENTRY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG maxEntries = OutputBufferLength / sizeof(SHELLCODE_LOG_ENTRY);

    ULONG entriesRead = DataManager_GetLogEntries(
        (PSHELLCODE_LOG_ENTRY)OutputBuffer,
        maxEntries
    );

    *BytesReturned = entriesRead * sizeof(SHELLCODE_LOG_ENTRY);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
    DBG_PRINT("IoControl_HandleGetLogEntries: Returned %lu entries\n", entriesRead);
#endif

    return STATUS_SUCCESS;
}

// ============================================================================
// 测试连接处理
// ============================================================================

typedef struct _TEST_CONNECTION_RESPONSE {
    ULONG       DriverVersion;
    ULONG       TotalProcesses;
    ULONG       TotalRegions;
    BOOLEAN     IsInitialized;
    CHAR        DriverName[32];
} TEST_CONNECTION_RESPONSE, * PTEST_CONNECTION_RESPONSE;

NTSTATUS IoControl_HandleTestConnection(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    *BytesReturned = 0;

    if (!OutputBuffer || OutputBufferLength < sizeof(TEST_CONNECTION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PTEST_CONNECTION_RESPONSE response = (PTEST_CONNECTION_RESPONSE)OutputBuffer;

    RtlZeroMemory(response, sizeof(TEST_CONNECTION_RESPONSE));

    response->DriverVersion = 0x00010000;  // 1.0.0.0
    response->TotalProcesses = g_DataManager.TotalProcessCount;
    response->TotalRegions = g_DataManager.TotalRegionCount;
    response->IsInitialized = g_DataManager.IsInitialized;

    RtlStringCbCopyA(response->DriverName, sizeof(response->DriverName), "ShellcodeDetector");

    *BytesReturned = sizeof(TEST_CONNECTION_RESPONSE);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
    DBG_PRINT("IoControl_HandleTestConnection: Connection test successful\n");
#endif

    return STATUS_SUCCESS;
}

// ============================================================================
// 模块隐藏请求处理
// ============================================================================

NTSTATUS IoControl_HandleHideModule(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    *BytesReturned = 0;

    // 接受 64-bit DLL（48 字节）或 32-bit WoW64 DLL（24 字节）发来的缓冲区
    if (!InputBuffer || InputBufferLength < sizeof(HIDE_MODULE_REQUEST_32)) {
        DBG_PRINT("IoControl_HandleHideModule: Invalid input buffer (len=%lu, min=%lu)\n",
            InputBufferLength, (ULONG)sizeof(HIDE_MODULE_REQUEST_32));
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 根据缓冲区大小选择解析路径
    ULONG      processId;
    ULONG_PTR  moduleBase;
    SIZE_T     moduleSize;
    BOOLEAN    isWow64;

    if (InputBufferLength >= sizeof(HIDE_MODULE_REQUEST)) {
        PHIDE_MODULE_REQUEST req = (PHIDE_MODULE_REQUEST)InputBuffer;
        processId  = req->ProcessId;
        moduleBase = req->ModuleBase;
        moduleSize = req->ModuleSize;
        isWow64    = req->IsWow64;
    } else {
        // 32-bit DLL 发来的缩减版请求
        PHIDE_MODULE_REQUEST_32 req32 = (PHIDE_MODULE_REQUEST_32)InputBuffer;
        processId  = req32->ProcessId;
        moduleBase = (ULONG_PTR)req32->ModuleBase;
        moduleSize = (SIZE_T)req32->ModuleSize;
        isWow64    = req32->IsWow64;
    }

    if (!processId || !moduleBase) {
        DBG_PRINT("IoControl_HandleHideModule: Invalid request parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    DBG_PRINT("IoControl_HandleHideModule: PID=%lu ModuleBase=%p Size=0x%zX IsWow64=%d\n",
        processId, (PVOID)moduleBase, moduleSize, (int)isWow64);

    // 获取 EPROCESS
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)processId, &process);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("IoControl_HandleHideModule: PsLookupProcessByProcessId failed (0x%08X)\n",
            status);
        return status;
    }

    // 执行 L1-L4 模块隐藏
    status = Utils_HideModuleInProcess(
        process,
        moduleBase,
        moduleSize,
        isWow64
    );

    ObDereferenceObject(process);

    if (NT_SUCCESS(status)) {
        DBG_PRINT("IoControl_HandleHideModule: Module hidden successfully\n");

        // DLL 发送 IOCTL_HIDE_MODULE 表明 KiDispatchHook_Install 已成功完成，
        // 此时启用 KiUED Hook 保护（阻止后续对 KiUED 页的权限修改）
        PPROCESS_NODE node = DataManager_FindProcess((HANDLE)(ULONG_PTR)processId);
        if (node) {
            PVOID kiUedAddress = NULL;
            ExAcquirePushLockExclusive(&node->NodeLock);
            kiUedAddress = node->KiUedAddress;
            node->HookProtectionActive = TRUE;
            ExReleasePushLockExclusive(&node->NodeLock);

            if (kiUedAddress) {
                SyscallHook_SetKiUedAddress(kiUedAddress);
            }
            DBG_PRINT("IoControl_HandleHideModule: HookProtectionActive = TRUE for PID %lu\n",
                processId);
            DataManager_ReleaseProcess(node);
        }
    } else {
        DBG_PRINT("IoControl_HandleHideModule: Hide failed (0x%08X)\n", status);
    }

    return status;
}
