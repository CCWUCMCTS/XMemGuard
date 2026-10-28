// ============================================================================
// FileLogger.cpp - 权限变动文件日志模块实现
//
// 实现策略：KMUTEX 直写
//
// 全局状态：
//   g_LogFileHandle - 驱动加载时打开，卸载时关闭，生命周期与驱动相同
//   g_LogFileMutex  - KMUTEX，序列化并发追加写入
//
// 关键 IRQL 约束：
//   FAST_MUTEX（ExAcquireFastMutex）将 IRQL 提升至 APC_LEVEL，
//   但 ZwWriteFile（FILE_SYNCHRONOUS_IO_NONALERT）在内部调用
//   KeWaitForSingleObject，该函数在 APC_LEVEL 无法完成等待，
//   导致 Detour 回调永久阻塞，injector 的 VirtualAllocEx 永远不返回。
//   使用 KMUTEX（KeWaitForMutexObject/KeReleaseMutex）：
//   等待时不提升 IRQL，IRQL 保持 PASSIVE_LEVEL，ZwWriteFile 正常工作。
//
// 写入流程：
//   1. KeQuerySystemTime -> ExSystemTimeToLocalTime -> RtlTimeToTimeFields
//   2. _snprintf_s 在 512 字节栈缓冲区上格式化完整日志行（避免堆分配）
//   3. KeWaitForMutexObject -> ZwWriteFile -> KeReleaseMutex
//
// 错误处理：
//   文件写入失败仅 DBG_PRINT 警告，不影响检测主逻辑。
//   FileLogger_Initialize 未调用或失败时，LogProtectionChange 为空操作。
// ============================================================================

#include "FileLogger.hpp"
#include <stdio.h>    // _snprintf_s（内核模式安全格式化函数）

// ============================================================================
// 全局状态
// ============================================================================

// 日志文件句柄（NULL 表示未初始化或已关闭）
static HANDLE     g_LogFileHandle = NULL;

// 并发写入互斥锁
// KMUTEX：等待时不提升 IRQL（保持 PASSIVE_LEVEL），与 ZwWriteFile 同步 I/O 兼容
// 不可使用 FAST_MUTEX（ExAcquireFastMutex 将 IRQL 提升至 APC_LEVEL，
// 导致 ZwWriteFile 内部 KeWaitForSingleObject 永久阻塞）
static KMUTEX g_LogFileMutex;

// ============================================================================
// 内部工具：本地时间
// ============================================================================

// 将当前 UTC 系统时间转为本地时间字段，填入 TIME_FIELDS 结构。
// TIME_FIELDS 字段：Year / Month / Day / Hour / Minute / Second / Milliseconds
static VOID GetLocalTimeFields(_Out_ PTIME_FIELDS TimeFields)
{
    LARGE_INTEGER sysTime, localTime;
    KeQuerySystemTime(&sysTime);                   // 获取 UTC 时间（100ns 精度）
    ExSystemTimeToLocalTime(&sysTime, &localTime); // 按系统时区偏移转本地时间
    RtlTimeToTimeFields(&localTime, TimeFields);   // 分解为年/月/日/时/分/秒/毫秒
}

// ============================================================================
// 内部工具：追加写入（调用方需持锁）
// ============================================================================

// 将格式化好的 ASCII 字符串追加写入日志文件。
// 本函数不加锁，调用方必须已持有 g_LogFileMutex。
static VOID WriteLineToFile(_In_ PCSTR Line, _In_ SIZE_T Length)
{
    if (!g_LogFileHandle || Length == 0) {
        return;
    }

    IO_STATUS_BLOCK iosb = { 0 };

    // ByteOffset 传 NULL：配合 FILE_APPEND_DATA 访问权限，
    // 文件系统自动定位到末尾追加，驱动无需维护显式文件偏移。
    NTSTATUS status = ZwWriteFile(
        g_LogFileHandle,
        NULL,           // 不使用事件对象
        NULL,           // 无 APC 例程
        NULL,           // 无 APC 上下文
        &iosb,
        (PVOID)Line,
        (ULONG)Length,
        NULL,           // ByteOffset = NULL -> 追加到末尾
        NULL            // 无写入 Key
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("FileLogger: ZwWriteFile failed (0x%08X)\n", status);
    }
}

// ============================================================================
// FileLogger_Initialize
// ============================================================================

NTSTATUS FileLogger_Initialize(VOID)
{
    // 初始化并发互斥锁（KMUTEX 在首次使用前必须调用此函数）
    KeInitializeMutex(&g_LogFileMutex, 0);

    // ---- 检查日志目录是否存在 ----
    // Common.hpp 中 LOG_DIR_PATH 指定的目录需要预先创建。
    // 若目录不存在，输出提示并返回失败。
    {
        UNICODE_STRING dirPath;
        RtlInitUnicodeString(&dirPath, LOG_DIR_PATH);

        OBJECT_ATTRIBUTES dirAttr;
        InitializeObjectAttributes(
            &dirAttr,
            &dirPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        );

        IO_STATUS_BLOCK dirIosb = { 0 };
        HANDLE hDir = NULL;
        NTSTATUS dirStatus = ZwCreateFile(
            &hDir,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &dirAttr,
            &dirIosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,          // 仅打开，不创建
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(dirStatus)) {
            DBG_PRINT("FileLogger: 日志目录不存在: %wZ (0x%08X)\n", &dirPath, dirStatus);
            DBG_PRINT("FileLogger: 请预先创建 LOG_DIR_PATH 指定的日志目录\n");
            g_LogFileHandle = NULL;
            return dirStatus;
        }

        ZwClose(hDir);
    }

    // 使用 Common.hpp 中定义的日志路径
    UNICODE_STRING logPath;
    RtlInitUnicodeString(&logPath, LOG_FILE_PATH);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(
        &objAttr,
        &logPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    IO_STATUS_BLOCK iosb = { 0 };

    NTSTATUS status = ZwCreateFile(
        &g_LogFileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("FileLogger: ZwCreateFile failed (0x%08X), path: %wZ\n", status, &logPath);
        g_LogFileHandle = NULL;
        return status;
    }

    // 写入 Session 起始分隔行（便于在驱动多次加载时区分各次会话）
    TIME_FIELDS tf;
    GetLocalTimeFields(&tf);

    CHAR header[256];
    SIZE_T headerLen = 0;
    _snprintf_s(header, sizeof(header), _TRUNCATE,
        "\r\n===== ShellcodeDetector Session Start"
        " [%04d-%02d-%02d %02d:%02d:%02d] =====\r\n",
        tf.Year, tf.Month, tf.Day,
        tf.Hour, tf.Minute, tf.Second);
    headerLen = strlen(header);
    WriteLineToFile(header, headerLen);

    DBG_PRINT("FileLogger: Initialized, log -> %wZ\n", &logPath);
    return STATUS_SUCCESS;
}

// ============================================================================
// FileLogger_Cleanup
// ============================================================================

VOID FileLogger_Cleanup(VOID)
{
    if (!g_LogFileHandle) {
        return;
    }

    // 写入 Session 结束分隔行
    TIME_FIELDS tf;
    GetLocalTimeFields(&tf);

    CHAR footer[256];
    SIZE_T footerLen = 0;
    _snprintf_s(footer, sizeof(footer), _TRUNCATE,
        "===== ShellcodeDetector Session End"
        " [%04d-%02d-%02d %02d:%02d:%02d] =====\r\n",
        tf.Year, tf.Month, tf.Day,
        tf.Hour, tf.Minute, tf.Second);
    footerLen = strlen(footer);
    WriteLineToFile(footer, footerLen);

    ZwClose(g_LogFileHandle);
    g_LogFileHandle = NULL;
    DBG_PRINT("FileLogger: Cleanup complete\n");
}

// ============================================================================
// FileLogger_LogEvent — 通用结构化事件日志
// 格式: [timestamp] [K] EVENT=<type> <key=value ...>
// ============================================================================

VOID FileLogger_LogEvent(
    _In_ PCSTR EventType,
    _In_ PCSTR FormatArgs
)
{
    if (!g_LogFileHandle) {
        return;
    }

    TIME_FIELDS tf;
    GetLocalTimeFields(&tf);

    CHAR buf[512];
    _snprintf_s(
        buf, sizeof(buf), _TRUNCATE,
        "[%04d-%02d-%02d %02d:%02d:%02d.%03d] [K] EVENT=%s %s\r\n",
        tf.Year, tf.Month, tf.Day,
        tf.Hour, tf.Minute, tf.Second, tf.Milliseconds,
        EventType,
        FormatArgs ? FormatArgs : ""
    );

    SIZE_T bufLen = strlen(buf);

    KeWaitForMutexObject(&g_LogFileMutex, Executive, KernelMode, FALSE, NULL);
    WriteLineToFile(buf, bufLen);
    KeReleaseMutex(&g_LogFileMutex, FALSE);
}

// ============================================================================
// FileLogger_LogProtectionChange — INTERCEPT 事件的便捷封装
// ============================================================================

VOID FileLogger_LogProtectionChange(
    _In_     PCSTR     SyscallName,
    _In_     ULONG     InitiatorPid,
    _In_     PCHAR     InitiatorName,
    _In_     ULONG     TargetPid,
    _In_     PCHAR     TargetName,
    _In_     ULONG_PTR BaseAddress,
    _In_     SIZE_T    RegionSize,
    _In_     ULONG     OriginalProtect,
    _In_     ULONG     ModifiedProtect,
    _In_     NTSTATUS  SyscallStatus,
    _In_opt_ PCSTR     ExtraParams
)
{
    if (!g_LogFileHandle) {
        return;
    }

    PCSTR iName = (InitiatorName && InitiatorName[0]) ? InitiatorName : "?";
    PCSTR tName = (TargetName    && TargetName[0])    ? TargetName    : "?";

    CHAR args[400];
    _snprintf_s(
        args, sizeof(args), _TRUNCATE,
        "Syscall=%s SrcPID=%lu SrcName=%s DstPID=%lu DstName=%s "
        "Addr=%08llX Size=%llX OrigProt=%s NewProt=%s Status=0x%08X%s%s",
        SyscallName,
        InitiatorPid, iName,
        TargetPid, tName,
        (ULONG64)BaseAddress, (ULONG64)RegionSize,
        ProtectionToString(OriginalProtect),
        ProtectionToString(ModifiedProtect),
        (ULONG)SyscallStatus,
        (ExtraParams && ExtraParams[0]) ? " " : "",
        (ExtraParams && ExtraParams[0]) ? ExtraParams : ""
    );

    FileLogger_LogEvent("INTERCEPT", args);
}
