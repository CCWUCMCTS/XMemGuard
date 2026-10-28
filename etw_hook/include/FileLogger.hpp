#pragma once
// ============================================================================
// FileLogger.hpp - 权限变动文件日志模块接口
//
// 功能：将驱动拦截到的跨进程内存权限修改事件实时追加写入日志文件。
//
// 设计（KMUTEX 直写）：
//   - 被拦截的 syscall 均在 PASSIVE_LEVEL 执行，可直接调用 ZwWriteFile。
//   - 使用 KMUTEX（KeWaitForMutexObject）序列化并发写入：
//     KMUTEX 等待时不提升 IRQL，与 FILE_SYNCHRONOUS_IO_NONALERT 兼容。
//     FAST_MUTEX（ExAcquireFastMutex）会将 IRQL 提升到 APC_LEVEL，
//     导致 ZwWriteFile 内部 KeWaitForSingleObject 无法完成而永久阻塞。
//   - 日志路径由 Common.hpp 中 LOG_FILE_PATH 宏决定。
//   - 初始化时检查 LOG_DIR_PATH 目录是否存在，不存在则 DBG_PRINT 提示并返回失败。
//   - FileLogger_Initialize 失败不阻断驱动加载，文件日志为可选增强功能。
// ============================================================================

#include <ntifs.h>
#include "Common.hpp"

// ============================================================================
// 初始化与清理
// ============================================================================

// 打开（或创建）日志文件，初始化 KMUTEX，写入 Session 起始标记行。
// 应在 DriverEntry 中、DataManager_Initialize 成功之后调用。
// 返回值：STATUS_SUCCESS 表示文件已就绪；
//        失败时仅 DBG_PRINT 警告，驱动继续正常加载。
NTSTATUS FileLogger_Initialize(VOID);

// 写入 Session 结束标记行，并关闭文件句柄。
// 应在 DriverUnload 末尾调用（DataManager_Cleanup 之后）。
VOID FileLogger_Cleanup(VOID);

// ============================================================================
// 核心日志接口
// ============================================================================

// 通用事件日志：写入一行 [timestamp] [K] EVENT=<type> <key=value ...> 格式的结构化日志。
// EventType  - 事件类型（如 "INTERCEPT"、"WRITE_MARK"、"EXCEPTION_REPORT" 等）
// FormatArgs - 预格式化的 key=value 字符串（调用方在栈上 _snprintf_s 好再传入）
VOID FileLogger_LogEvent(
    _In_ PCSTR EventType,
    _In_ PCSTR FormatArgs
);

// 记录一次权限变动事件到文件（INTERCEPT 事件的便捷封装，内部调用 FileLogger_LogEvent）。
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
);
