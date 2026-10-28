#pragma once
// ============================================================================
// DataManager.hpp - 核心数据结构定义
// 使用 Hash Table + AVL Tree 实现高效的进程和内存区域管理
// ============================================================================

#include <ntifs.h>
#include <ntddk.h>
#include "Common.hpp"

// ============================================================================
// 前置声明
// ============================================================================
struct _MEMORY_REGION_NODE;
struct _PROCESS_NODE;

// ============================================================================
// 内存区域节点 (AVL Tree节点)
// ============================================================================
typedef struct _MEMORY_REGION_NODE {
    // AVL Tree 使用的标准链接
    RTL_BALANCED_LINKS  BalancedLinks;

    // 内存区域信息
    ULONG_PTR           StartAddress;       // 起始地址
    ULONG_PTR           EndAddress;         // 结束地址 (不含)
    ULONG               CurrentProtection;  // 当前保护属性
    ULONG               OriginalProtection; // 原始保护属性
    HANDLE              InitiatorPid;       // 攻击者进程ID
    BOOLEAN             IsDirty;            // 是否被写入
    LARGE_INTEGER       CreateTime;         // 创建时间

} MEMORY_REGION_NODE, * PMEMORY_REGION_NODE;

// ============================================================================
// 进程节点 (Hash Table桶中的链表节点)
// ============================================================================
typedef struct _PROCESS_NODE {
    // 链表链接
    LIST_ENTRY          HashLink;           // Hash桶链接

    // 进程标识
    HANDLE              ProcessId;          // 进程ID
    LONGLONG            ProcessCreateTime;  // 进程创建时间 (避免PID重用冲突)

    // 内存区域AVL树
    RTL_AVL_TABLE       MemoryRegionTable;  // AVL树
    ULONG               RegionCount;        // 区域数量

    // 用户态Hook状态
    BOOLEAN             IsHookInstalled;    // 是否已安装Hook（ZwCreateThreadEx 线程已完成）
    BOOLEAN             DllConnected;       // DllMain 已运行并成功打开驱动设备
    BOOLEAN             HookProtectionActive; // KiUED Hook 保护已激活（IOCTL_HIDE_MODULE 后置 TRUE）
    BOOLEAN             HookPending;        // Hook 因目标进程未初始化失败（疑似 Process Hollowing），不再重试
    PVOID               ShellcodeBase;      // 注入的Shellcode地址
    SIZE_T              ShellcodeSize;      // Shellcode大小
    PVOID               TrampolineAddr;     // Trampoline地址
    HANDLE              DeviceHandle;       // 目标进程中打开的驱动设备句柄
    PVOID               KiUedAddress;       // KiUserExceptionDispatcher 地址（用于 Hook 保护）

    // 节点锁 (细粒度锁)
    EX_PUSH_LOCK        NodeLock;

    // 引用计数
    // 引用计数：由 FindProcess / FindOrCreateProcess 递增，由 ReleaseProcess 递减。
    // 当 PendingRemoval 为 TRUE 且本值降为 0 时，节点由认领者负责释放
    //（见 DataManager_FreeProcessNodeInternal）。
    volatile LONG       ReferenceCount;

    // PendingRemoval：由 DataManager_RemoveProcess 在将节点从哈希链表摘除后置 TRUE。
    // 置位后 FindProcess / FindOrCreateProcess 不再能访问到本节点
    //（两者在桶锁下遍历链表，节点已不在链表中）。
    //
    // 访问顺序保证（认领式延迟释放模式）：
    //   RemoveProcess  ：volatile 写 PendingRemoval + KeMemoryBarrier() +
    //                    CAS(ReferenceCount: 0 -> -1)
    //   ReleaseProcess ：InterlockedDecrement（x86/x64 含完整内存屏障）后读本标志
    // 保证两者中恰好只有一方的 CAS 观察到 RefCount==0，节点被且仅被释放一次。
    volatile BOOLEAN    PendingRemoval;
} PROCESS_NODE, * PPROCESS_NODE;

// ============================================================================
// Hash桶结构
// ============================================================================
typedef struct _HASH_BUCKET {
    LIST_ENTRY          ListHead;           // 链表头
    EX_PUSH_LOCK        BucketLock;         // 桶锁
} HASH_BUCKET, * PHASH_BUCKET;

// ============================================================================
// 数据管理器主结构
// ============================================================================
typedef struct _DATA_MANAGER {
    // Hash表
    HASH_BUCKET         ProcessTable[PROCESS_HASH_TABLE_SIZE];

    // 全局统计
    volatile LONG       TotalProcessCount;
    volatile LONG       TotalRegionCount;

    // 日志环形缓冲
    PSHELLCODE_LOG_ENTRY LogBuffer;
    volatile LONG       LogHead;
    volatile LONG       LogTail;
    ULONG               LogCapacity;
    KSPIN_LOCK          LogLock;

    // 初始化标志
    BOOLEAN             IsInitialized;

} DATA_MANAGER, * PDATA_MANAGER;

// ============================================================================
// 全局数据管理器实例
// ============================================================================
extern DATA_MANAGER g_DataManager;

// ============================================================================
// 初始化与清理
// ============================================================================

// 初始化数据管理器
NTSTATUS DataManager_Initialize(VOID);

// 清理数据管理器
VOID DataManager_Cleanup(VOID);

// ============================================================================
// 进程管理
// ============================================================================

// 查找或创建进程节点
// 若进程不存在则创建，返回带引用计数的节点
PPROCESS_NODE DataManager_FindOrCreateProcess(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_opt_ PBOOLEAN WasCreated
);

// 查找进程节点 (加引用)
PPROCESS_NODE DataManager_FindProcess(
    _In_ HANDLE ProcessId
);

// 释放进程节点引用
VOID DataManager_ReleaseProcess(
    _In_ PPROCESS_NODE ProcessNode
);

// 删除进程节点
VOID DataManager_RemoveProcess(
    _In_ HANDLE ProcessId
);

// 标记进程已安装Hook
VOID DataManager_SetProcessHooked(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ PVOID ShellcodeBase,
    _In_ SIZE_T ShellcodeSize,
    _In_ PVOID TrampolineAddr,
    _In_ HANDLE DeviceHandle
);

// ============================================================================
// 内存区域管理
// ============================================================================

// 添加受控内存区域
NTSTATUS DataManager_AddMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG CurrentProtection,
    _In_ ULONG OriginalProtection,
    _In_ HANDLE InitiatorPid
);

// 查找内存区域 (按地址)
PMEMORY_REGION_NODE DataManager_FindMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address
);

// 查找内存区域 (通过PID和地址的组合查询)
PMEMORY_REGION_NODE DataManager_FindMemoryRegionByPidAndAddress(
    _In_ HANDLE ProcessId,
    _In_ ULONG_PTR Address,
    _Out_opt_ PPROCESS_NODE* OutProcessNode
);

// 查询内存区域快照（在锁保护下复制节点内容，避免返回悬空 AVL 节点指针）
BOOLEAN DataManager_QueryMemoryRegionSnapshot(
    _In_ HANDLE ProcessId,
    _In_ ULONG_PTR Address,
    _Out_ PMEMORY_REGION_NODE RegionSnapshot
);

// 更新内存区域
NTSTATUS DataManager_UpdateMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address,
    _In_opt_ PULONG NewCurrentProtection,
    _In_opt_ PULONG NewOriginalProtection,
    _In_opt_ PBOOLEAN NewIsDirty,
    _In_opt_ PSIZE_T ExtendSize
);

// 删除内存区域
NTSTATUS DataManager_RemoveMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address
);

// ============================================================================
// 日志管理
// ============================================================================

// 添加日志条目
NTSTATUS DataManager_AddLogEntry(
    _In_ PSHELLCODE_LOG_ENTRY Entry
);

// 获取日志条目
ULONG DataManager_GetLogEntries(
    _Out_writes_(MaxEntries) PSHELLCODE_LOG_ENTRY Buffer,
    _In_ ULONG MaxEntries
);

// 清空日志
VOID DataManager_ClearLogs(VOID);

// ============================================================================
// 调试和统计
// ============================================================================

// 打印统计信息
VOID DataManager_PrintStatistics(VOID);

// 转储所有进程 (调试用)
VOID DataManager_DumpAllProcesses(VOID);

//#endif // DATA_MANAGER_HPP
