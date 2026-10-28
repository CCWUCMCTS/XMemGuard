#pragma once
// ============================================================================
// Utils.hpp - 工具库头文件
// 包含LDE引擎类、内存操作、进程工具、SSDT查询等
// ============================================================================

#include <ntifs.h>
#include "Common.hpp"

#define PROCESS_QUERY_INFORMATION (0x0400)

// ============================================================================
// 外部函数声明
// ============================================================================

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

EXTERN_C NTSTATUS NTAPI ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

// ============================================================================
// SSDT 结构定义
// ============================================================================

typedef struct _SYSTEM_SERVICE_TABLE {
    PVOID       ServiceTableBase;
    PVOID       ServiceCounterTableBase;
    ULONGLONG   NumberOfServices;
    PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

// 全局SSDT指针
extern PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable;

// ============================================================================
// PEB/LDR 结构定义 (手动枚举定义)
// ============================================================================

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, * PPEB;

// 32位结构 (WoW64)
typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;



typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

// ============================================================================
// LDE (Length Disassembly Engine) - 指令长度计算器
// 仅支持x64，用于计算Hook的Trampoline大小
// ============================================================================

// 计算单条x64指令的长度
// 返回：指针为0表示无法解析
ULONG LDE_GetInstructionLength(
    _In_ PVOID Address
);

// 计算需要复制的最小指令集以容纳跳转指令
// JmpSize: 需要插入的跳转指令的大小(通常为14字节的绝对跳转)
// 返回：需要复制的指令总字节数
ULONG LDE_CalculateTrampolineSize(
    _In_ PVOID Address,
    _In_ ULONG JmpSize
);

// ============================================================================
// 内存操作工具
// ============================================================================

// 安全读取用户态内存
NTSTATUS Utils_SafeReadUserMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
);

// 安全写入用户态内存
NTSTATUS Utils_SafeWriteUserMemory(
    _In_ PVOID DestinationAddress,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
);

// 使用MDL映射并写入内存（可写入只读内存）
NTSTATUS Utils_WriteMemoryWithMdl(
    _In_ PVOID DestinationAddress,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
);

// 在目标进程中分配内存
NTSTATUS Utils_AllocateUserMemory(
    _In_ HANDLE ProcessHandle,
    _Out_ PVOID* BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG Protection
);

// 释放目标进程中的内存
NTSTATUS Utils_FreeUserMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress
);

// ============================================================================
// 进程工具
// ============================================================================

// 通过PID获取进程名
PCHAR Utils_GetProcessNameByPid(
    _In_ HANDLE ProcessId
);

// 通过句柄获取PID及创建时间
NTSTATUS Utils_GetPidFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId,
    _Out_opt_ PLONGLONG CreateTime
);

// 获取父进程ID
NTSTATUS Utils_GetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
);

// 判断是否为父子进程关系
BOOLEAN Utils_AreParentChildProcesses(
    _In_ HANDLE ParentPid,
    _In_ HANDLE ChildPid
);

// 查找进程的EPROCESS
PEPROCESS Utils_LookupProcessByPid(
    _In_ HANDLE ProcessId
);

// ============================================================================
// 模块工具
// ============================================================================

// 获取用户态模块地址
PVOID Utils_GetUserModuleBase(
    _In_ PEPROCESS Process,
    _In_ PUNICODE_STRING ModuleName,
    _In_ BOOLEAN IsWow64
);

// 获取模块导出函数地址
PVOID Utils_GetModuleExportAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
);

// 获取ntdll.dll中函数地址
PVOID Utils_GetNtdllExportAddress(
    _In_ PEPROCESS Process,
    _In_ PCSTR FunctionName,
    _In_ BOOLEAN IsWow64
);

// ============================================================================
// SSDT查询
// ============================================================================

// 初始化SSDT指针
NTSTATUS Utils_InitializeSSDT(
    _In_ PDRIVER_OBJECT DriverObject
);

// 通过函数名获取SSDT索引
ULONG Utils_GetSSDTIndex(
    _In_ PCSTR FunctionName
);

// 通过索引获取SSDT函数地址
PVOID Utils_GetSSDTFunctionAddress(
    _In_ ULONG Index
);

// ============================================================================
// 系统调用号查询
// ============================================================================

// 获取Nt函数的系统调用号
USHORT Utils_GetSyscallNumber(
    _In_ PCSTR NtFunctionName
);

// ============================================================================
// 驱动签名绕过
// ============================================================================

BOOLEAN Utils_BypassCheckSign(
    _In_ PDRIVER_OBJECT DriverObject
);

// ============================================================================
// 调试工具
// ============================================================================

// 打印十六进制转储
VOID Utils_HexDump(
    _In_ PVOID Address,
    _In_ SIZE_T Length,
    _In_opt_ PCSTR Label
);

// ============================================================================
// 模块隐藏 L1-L4 (IOCTL_HIDE_MODULE 触发)
// ============================================================================

// 对目标进程中指定模块执行四级隐藏:
//   L1: PEB64.Ldr 三链表摘除
//   L2: MZ/PE 头覆零
//   L3: VAD 类型修改为私有内存
//   L4: WoW64 进程同步摘除 PEB32.Ldr 条目
NTSTATUS Utils_HideModuleInProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR ModuleBase,
    _In_ SIZE_T    ModuleSize,
    _In_ BOOLEAN   IsWow64
);

