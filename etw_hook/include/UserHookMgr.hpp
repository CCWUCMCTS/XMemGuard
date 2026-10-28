#pragma once
// ============================================================================
// UserHookMgr.hpp - 用户态Hook管理器
// 负责向目标进程注入Shellcode并Hook KiUserExceptionDispatcher
// ============================================================================

#include <ntifs.h>
#include "Common.hpp"
#include "DataManager.hpp"

// ============================================================================
// Hook状态枚举
// ============================================================================

typedef enum _USER_HOOK_STATE {
    HookStateNone = 0,          // 未安装
    HookStateInstalling,        // 正在安装
    HookStateInstalled,         // 已安装
    HookStateFailed,            // 安装失败
    HookStateRemoving           // 正在卸载
} USER_HOOK_STATE;

// ============================================================================
// 进程Hook信息
// ============================================================================

typedef struct _PROCESS_HOOK_INFO {
    HANDLE              ProcessId;              // 进程ID
    PEPROCESS           Process;                // EPROCESS指针
    BOOLEAN             IsWow64;                // 是否为WoW64进程
    USER_HOOK_STATE     State;                  // Hook状态

    // 注入的内存信息
    PVOID               ShellcodeBaseUser;      // 用户态Shellcode地址
    SIZE_T              ShellcodeSize;          // Shellcode大小
    PVOID               TrampolineAddr;         // Trampoline地址

    // 原始函数信息
    PVOID               OriginalFuncAddr;       // KiUserExceptionDispatcher地址
    UCHAR               OriginalBytes[32];      // 原始字节备份
    SIZE_T              OriginalBytesSize;      // 原始字节大小

    // 系统调用号缓存
    USHORT              SyscallNtDeviceIoControlFile;
    USHORT              SyscallNtContinue;
    USHORT              SyscallNtProtectVirtualMemory;

    // 目标进程中打开的设备句柄
    HANDLE              DeviceHandle;

} PROCESS_HOOK_INFO, * PPROCESS_HOOK_INFO;

// ============================================================================
// 模块初始化与清理
// ============================================================================

// 初始化用户态Hook管理器
NTSTATUS UserHookMgr_Initialize(VOID);

// 清理用户态Hook管理器
VOID UserHookMgr_Cleanup(VOID);

// ============================================================================
// Hook管理API
// ============================================================================

// 向目标进程安装Hook
// 此函数应在Attach到目标进程后调用
NTSTATUS UserHookMgr_InstallHook(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime
);

// 从目标进程卸载Hook
NTSTATUS UserHookMgr_RemoveHook(
    _In_ HANDLE ProcessId
);

// 查询进程是否已安装Hook
BOOLEAN UserHookMgr_IsHookInstalled(
    _In_ HANDLE ProcessId
);

// ============================================================================
// 异常处理API (由IOCTL处理器使用)
// ============================================================================

// 处理用户态上报的异常
NTSTATUS UserHookMgr_HandleException(
    _In_ PEXCEPTION_REPORT_PACKET Report,
    _Out_ PEXCEPTION_RESPONSE_PACKET Response
);

// ============================================================================
// 内部辅助函数 (仅供模块内部使用，暴露在头文件中以便单元测试)
// ============================================================================


// 获取KiUserExceptionDispatcher地址
PVOID UserHookMgr_GetKiUserExceptionDispatcher(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN IsWow64
);

// 在目标进程中分配内存
NTSTATUS UserHookMgr_AllocateMemoryInProcess(
    _In_ PEPROCESS Process,
    _Out_ PVOID* BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG Protection
);

// 写入目标进程内存
NTSTATUS UserHookMgr_WriteProcessMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID TargetAddress,
    _In_ PVOID SourceBuffer,
    _In_ SIZE_T Size
);

// 读取目标进程内存
NTSTATUS UserHookMgr_ReadProcessMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID SourceAddress,
    _Out_ PVOID TargetBuffer,
    _In_ SIZE_T Size
);


