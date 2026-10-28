#pragma once
// ============================================================================
// SyscallHook.hpp - 系统调用Hook接口
// 使用ETW Hook（InfinityHook等级）拦截内存相关系统调用
// ============================================================================

#include <ntifs.h>
#include "Common.hpp"


// ============================================================================
// Hook目标系统调用列表
// ============================================================================

typedef enum _HOOKED_SYSCALL {
    HookedSyscall_NtAllocateVirtualMemory = 0,
    HookedSyscall_NtAllocateVirtualMemoryEx,
    HookedSyscall_NtProtectVirtualMemory,
    HookedSyscall_NtMapViewOfSection,
    HookedSyscall_NtMapViewOfSectionEx,
    HookedSyscall_NtWriteVirtualMemory,
    HookedSyscall_NtQueryVirtualMemory,
    HookedSyscall_Max
} HOOKED_SYSCALL;

// ============================================================================
// Hook回调函数类型
// ============================================================================

// 通用的Pre-Hook回调
// 返回TRUE表示继续调用原始函数，FALSE表示拦截
typedef BOOLEAN(*SYSCALL_PRE_CALLBACK)(
    _In_ ULONG SyscallIndex,
    _Inout_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
    );

// 通用的Post-Hook回调
typedef VOID(*SYSCALL_POST_CALLBACK)(
    _In_ ULONG SyscallIndex,
    _In_ NTSTATUS ReturnValue,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
    );

// ============================================================================
// 初始化与清理
// ============================================================================

// 初始化系统调用Hook
NTSTATUS SyscallHook_Initialize(
    _In_ PDRIVER_OBJECT DriverObject
);

// 清理系统调用Hook
VOID SyscallHook_Cleanup(VOID);

// ============================================================================
// Hook控制
// ============================================================================

// 启用所有Hook
NTSTATUS SyscallHook_EnableAll(VOID);

// 禁用所有Hook
NTSTATUS SyscallHook_DisableAll(VOID);

// 启用特定Hook
NTSTATUS SyscallHook_Enable(
    _In_ HOOKED_SYSCALL SyscallId
);

// 禁用特定Hook
NTSTATUS SyscallHook_Disable(
    _In_ HOOKED_SYSCALL SyscallId
);

// ============================================================================
// 回调注册
// ============================================================================

// 注册Pre-Hook回调
NTSTATUS SyscallHook_RegisterPreCallback(
    _In_ SYSCALL_PRE_CALLBACK Callback
);

// 注册Post-Hook回调
NTSTATUS SyscallHook_RegisterPostCallback(
    _In_ SYSCALL_POST_CALLBACK Callback
);

// ============================================================================
// 状态查询
// ============================================================================

// 查询Hook是否已初始化
BOOLEAN SyscallHook_IsInitialized(VOID);

// 查询特定Hook是否已启用
BOOLEAN SyscallHook_IsEnabled(
    _In_ HOOKED_SYSCALL SyscallId
);

// 获取原始系统调用地址
PVOID SyscallHook_GetOriginalFunction(
    _In_ HOOKED_SYSCALL SyscallId
);

// 获取Detour函数地址
PVOID SyscallHook_GetDetourFunction(
    _In_ HOOKED_SYSCALL SyscallId
);

// ============================================================================
// KiUED Hook 保护
// ============================================================================

// 设置全局 KiUED 地址缓存（由 UserHookMgr 在首次安装 Hook 时调用）
// ntdll 在同一次启动中所有进程基址相同，因此只需设置一次
VOID SyscallHook_SetKiUedAddress(_In_ PVOID Address);
