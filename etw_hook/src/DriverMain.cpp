// ============================================================================
// Driver.cpp - 驱动主入口实现
// ============================================================================

#include "Driver.hpp"
#include "IoControl.hpp"
#include "DataManager.hpp"
#include "UserHookMgr.hpp"
#include "SyscallHook.hpp"
#include "Utils.hpp"
#include "FileLogger.hpp"   // 权限变动文件日志
#include <stdio.h>          // _snprintf_s

// ============================================================================
// 全局变量
// ============================================================================

PDRIVER_OBJECT g_DriverObject = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;

static BOOLEAN g_ProcessCallbackRegistered = FALSE;
static BOOLEAN g_ThreadCallbackRegistered  = FALSE;

// ============================================================================
// 进程通知回调
// ============================================================================

// ============================================================================
// 线程创建通知回调（调试用）
// 检测受监控进程中的新线程——用于判断 Shellcode 执行线程创建时 DllMain 是否已就绪
// ============================================================================

VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    if (!Create) return;  // 只关心线程创建

    // 仅检查受监控进程，避免对系统全局线程产生开销
    PPROCESS_NODE node = DataManager_FindProcess(ProcessId);
    if (!node) return;

    BOOLEAN hookInstalled = node->IsHookInstalled;
    BOOLEAN dllReady      = node->DllConnected;
    DataManager_ReleaseProcess(node);

    // 每个受监控进程的新线程都记录一条日志：
    //   HookInstalled = TRUE → ZwCreateThreadEx 线程已完成（DllMain 已执行）
    //   DllConnected  = TRUE → DllMain 已跑完并打开了驱动设备——Hook 已就位
    DBG_PRINT("ThreadNotifyCallback: PID=%lu 新线程 TID=%lu — "
        "HookInstalled=%d DllConnected=%d\n",
        (ULONG)(ULONG_PTR)ProcessId,
        (ULONG)(ULONG_PTR)ThreadId,
        (int)hookInstalled,
        (int)dllReady);

    CHAR args[192];
    _snprintf_s(args, sizeof(args), _TRUNCATE,
        "PID=%lu TID=%lu HookInstalled=%u DllConnected=%u",
        (ULONG)(ULONG_PTR)ProcessId,
        (ULONG)(ULONG_PTR)ThreadId,
        (ULONG)hookInstalled,
        (ULONG)dllReady);
    FileLogger_LogEvent("THREAD_CREATE", args);

    if (hookInstalled && !dllReady) {
        DBG_PRINT("ThreadNotifyCallback: *** 警告：PID=%lu 新线程创建时 DllMain 尚未就绪！***\n",
            (ULONG)(ULONG_PTR)ProcessId);
    }
}

// ZwQueryInformationProcess 在 WDK 头文件中未声明，手动补齐
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
);

// ============================================================================
// 崩溃检测：查询进程退出状态
// 用于 WoW64 进程 DEP 崩溃关联（内核去执行位 + 进程因 AV 退出 = 保护生效）
// ============================================================================
static NTSTATUS QueryProcessExitStatus(PEPROCESS Process)
{
    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        Process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) return STATUS_UNSUCCESSFUL;

    // PROCESS_BASIC_INFORMATION: ExitStatus 是第一个 NTSTATUS 字段
    struct { NTSTATUS ExitStatus; PVOID PebBaseAddress; ULONG_PTR AffinityMask;
             LONG BasePriority; ULONG_PTR UniqueProcessId; ULONG_PTR InheritedFromUniqueProcessId; } pbi;
    ULONG retLen = 0;
    status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    ZwClose(hProcess);

    if (NT_SUCCESS(status)) return pbi.ExitStatus;
    return STATUS_UNSUCCESSFUL;
}

VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo != NULL) {
        // 进程创建
        PCHAR processName = (PCHAR)PsGetProcessImageFileName(Process);
        PCSTR safeName = (processName && processName[0]) ? processName : "Unknown";

        DBG_PRINT("ProcessNotifyCallback: Process created - PID=%lu, Name=%s\n",
            (ULONG)(ULONG_PTR)ProcessId,
            safeName);

        CHAR args[256];
        _snprintf_s(args, sizeof(args), _TRUNCATE,
            "PID=%lu Name=%s ParentPID=%lu CreatingTID=%lu FileOpenName=%u",
            (ULONG)(ULONG_PTR)ProcessId,
            safeName,
            (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId,
            (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
            (ULONG)(CreateInfo->FileOpenNameAvailable ? 1 : 0));
        FileLogger_LogEvent("PROCESS_CREATE", args);
    }
    else {
        // 进程退出
        PCHAR procName = (PCHAR)PsGetProcessImageFileName(Process);
        PCSTR safeName = (procName && procName[0]) ? procName : "Unknown";
        NTSTATUS exitStatus = QueryProcessExitStatus(Process);

        DBG_PRINT("ProcessNotifyCallback: Process exiting - PID=%lu Name=%s ExitCode=0x%08X\n",
            (ULONG)(ULONG_PTR)ProcessId, safeName, exitStatus);

        // ================================================================
        // 崩溃检测：WoW64 进程有 INTERCEPT 记录但无 Hook → DEP 崩溃关联
        // ================================================================
        PPROCESS_NODE node = DataManager_FindProcess(ProcessId);
        if (node) {
            CHAR exitArgs[256];
            _snprintf_s(exitArgs, sizeof(exitArgs), _TRUNCATE,
                "PID=%lu Name=%s ExitCode=0x%08X RegionCount=%lu HookInstalled=%u DllConnected=%u",
                (ULONG)(ULONG_PTR)ProcessId,
                safeName,
                exitStatus,
                node->RegionCount,
                (ULONG)node->IsHookInstalled,
                (ULONG)node->DllConnected);
            FileLogger_LogEvent("PROCESS_EXIT", exitArgs);

            // 条件：有受控内存区域 + AV 退出 → DEP 保护生效（兜底检测）
            // 即使 Hook 已安装也报告——DLL 端可能因内部错误未能上报 EXCEPTION_REPORT，
            // 此处作为最后一道安全网。若 DLL 正常处理了异常，进程不会以 AV 退出，
            // 不会触发此路径（DLL 恢复执行用 NtContinue，终止用 0xDEAD1234）。
            if (node->RegionCount > 0) {
                if (exitStatus == STATUS_ACCESS_VIOLATION) {
                    // 有 INTERCEPT + AV 退出 = DEP 保护生效
                    DBG_PRINT("ProcessNotifyCallback: CRASH_DETECTED - PID=%lu (%s) "
                        "ExitCode=0x%08X RegionCount=%lu\n",
                        (ULONG)(ULONG_PTR)ProcessId, safeName,
                        exitStatus, node->RegionCount);

                    CHAR args[256];
                    _snprintf_s(args, sizeof(args), _TRUNCATE,
                        "PID=%lu Name=%s ExitCode=0x%08X RegionCount=%lu",
                        (ULONG)(ULONG_PTR)ProcessId, safeName,
                        exitStatus, node->RegionCount);
                    FileLogger_LogEvent("CRASH_DETECTED", args);
                } else {
                    // 有 INTERCEPT 但退出码非 AV（正常退出或其他原因）
                    DBG_PRINT("ProcessNotifyCallback: 受监控进程退出 - PID=%lu (%s) "
                        "ExitCode=0x%08X RegionCount=%lu (非 AV 崩溃)\n",
                        (ULONG)(ULONG_PTR)ProcessId, safeName,
                        exitStatus, node->RegionCount);
                }
            }
            DataManager_ReleaseProcess(node);
        } else {
            CHAR exitArgs[160];
            _snprintf_s(exitArgs, sizeof(exitArgs), _TRUNCATE,
                "PID=%lu Name=%s ExitCode=0x%08X RegionCount=0 HookInstalled=0 DllConnected=0",
                (ULONG)(ULONG_PTR)ProcessId,
                safeName,
                exitStatus);
            FileLogger_LogEvent("PROCESS_EXIT", exitArgs);
        }

        // 清理该进程的Hook
        if (UserHookMgr_IsHookInstalled(ProcessId)) {
            UserHookMgr_RemoveHook(ProcessId);
        }

        // 从数据管理器中移除
        DataManager_RemoveProcess(ProcessId);
    }
}

// ============================================================================
// 驱动卸载
// ============================================================================

EXTERN_C VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    DBG_PRINT("DriverUnload: Starting driver unload\n");

    // 注销线程通知回调
    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadCallbackRegistered = FALSE;
        DBG_PRINT("DriverUnload: Thread callback unregistered\n");
    }

    // 注销进程通知回调
    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        g_ProcessCallbackRegistered = FALSE;
        DBG_PRINT("DriverUnload: Process callback unregistered\n");
    }

    // 清理系统调用Hook
    SyscallHook_Cleanup();
    DBG_PRINT("DriverUnload: Syscall hooks cleaned up\n");

    // 清理用户态Hook管理器
    UserHookMgr_Cleanup();
    DBG_PRINT("DriverUnload: User hook manager cleaned up\n");

    // 清理数据管理器
    DataManager_Cleanup();
    DBG_PRINT("DriverUnload: Data manager cleaned up\n");

    // 关闭文件日志（写入 Session 结束标记，关闭文件句柄）
    FileLogger_Cleanup();
    DBG_PRINT("DriverUnload: File logger cleaned up\n");

    // 删除符号链接
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, LINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    DBG_PRINT("DriverUnload: Symbolic link deleted\n");

    // 删除设备对象
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
        DBG_PRINT("DriverUnload: Device object deleted\n");
    }

    DBG_PRINT("DriverUnload: Driver unload complete\n");
}

// ============================================================================
// 驱动入口
// ============================================================================

EXTERN_C NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLink;
    BOOLEAN deviceCreated = FALSE;
    BOOLEAN symLinkCreated = FALSE;

    DBG_PRINT("========================================\n");
    DBG_PRINT("ShellcodeDetector Driver Loading...\n");
    DBG_PRINT("========================================\n");

    g_DriverObject = DriverObject;

    // ============================================================
    // 1. 创建设备对象
    // ============================================================

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: IoCreateDevice failed (0x%08X)\n", status);
        goto Cleanup;
    }

    deviceCreated = TRUE;
    DBG_PRINT("DriverEntry: Device object created\n");

    // 设置设备标志
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // ============================================================
    // 2. 创建符号链接
    // ============================================================

    RtlInitUnicodeString(&symLink, LINK_NAME);

    status = IoCreateSymbolicLink(&symLink, &deviceName);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: IoCreateSymbolicLink failed (0x%08X)\n", status);
        goto Cleanup;
    }

    symLinkCreated = TRUE;
    DBG_PRINT("DriverEntry: Symbolic link created\n");

    // ============================================================
    // 3. 设置分发函数
    // ============================================================

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = IoControl_DispatchDefault;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IoControl_DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoControl_DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = IoControl_DispatchRead;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl_DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    DBG_PRINT("DriverEntry: Dispatch functions set\n");

    // ============================================================
    // 4. 初始化数据管理器
    // ============================================================

    status = DataManager_Initialize();

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: DataManager_Initialize failed (0x%08X)\n", status);
        goto Cleanup;
    }

    DBG_PRINT("DriverEntry: Data manager initialized\n");

    // ============================================================
    // 4.5 初始化文件日志模块
    //     失败时仅打印警告，不中断驱动加载（文件日志为可选增强）
    // ============================================================
    {
        NTSTATUS logStatus = FileLogger_Initialize();
        if (!NT_SUCCESS(logStatus)) {
            DBG_PRINT("DriverEntry: FileLogger_Initialize failed (0x%08X), file logging disabled\n", logStatus);
        } else {
            DBG_PRINT("DriverEntry: File logger initialized\n");
        }
    }

    // ============================================================
    // 5. 初始化用户态Hook管理器
    // ============================================================

    status = UserHookMgr_Initialize();

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: UserHookMgr_Initialize failed (0x%08X)\n", status);
        goto Cleanup;
    }

    DBG_PRINT("DriverEntry: User hook manager initialized\n");

    // ============================================================
    // 6. 初始化系统调用Hook
    // ============================================================

    status = SyscallHook_Initialize(DriverObject);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: SyscallHook_Initialize failed (0x%08X)\n", status);
        // 非致命错误，继续
    }
    else {
        // 启用所有Hook
        status = SyscallHook_EnableAll();

        if (!NT_SUCCESS(status)) {
            DBG_PRINT("DriverEntry: SyscallHook_EnableAll failed (0x%08X)\n", status);
        }
        else {
            DBG_PRINT("DriverEntry: Syscall hooks enabled\n");
        }
    }

    // ============================================================
    // 7. 绕过签名检查
    // ============================================================

    Utils_BypassCheckSign(DriverObject);
    DBG_PRINT("DriverEntry: Signature check bypassed\n");

    // ============================================================
    // 8. 注册进程通知回调
    // ============================================================

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: PsSetCreateProcessNotifyRoutineEx failed (0x%08X)\n", status);
        // 非致命错误，继续
    }
    else {
        g_ProcessCallbackRegistered = TRUE;
        DBG_PRINT("DriverEntry: Process callback registered\n");
    }

    // ============================================================
    // 9. 注册线程创建通知回调（调试：检测受监控进程中的新线程）
    // ============================================================

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("DriverEntry: PsSetCreateThreadNotifyRoutine failed (0x%08X)\n", status);
        // 非致命，不中断加载
    }
    else {
        g_ThreadCallbackRegistered = TRUE;
        DBG_PRINT("DriverEntry: Thread callback registered\n");
    }



    // ============================================================
    // 成功
    // ============================================================

    DBG_PRINT("========================================\n");
    DBG_PRINT("ShellcodeDetector Driver Loaded!\n");
    DBG_PRINT("========================================\n");

    return STATUS_SUCCESS;

Cleanup:
    // 清理已创建的资源

    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadCallbackRegistered = FALSE;
    }

    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        g_ProcessCallbackRegistered = FALSE;
    }

    SyscallHook_Cleanup();
    UserHookMgr_Cleanup();
    DataManager_Cleanup();

    if (symLinkCreated) {
        IoDeleteSymbolicLink(&symLink);
    }

    if (deviceCreated) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DBG_PRINT("DriverEntry: Driver load failed (0x%08X)\n", status);

    return status;
}
