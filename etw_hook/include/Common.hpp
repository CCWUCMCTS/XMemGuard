#pragma once
// ============================================================================
// Common.hpp - 公共定义、IOCTL码、共享数据结构
// ============================================================================

#ifdef _KERNEL_MODE
#include <ntifs.h>
#include <ntddk.h>
#else
#include <windows.h>
#include <winternl.h>
#endif

// ============================================================================
// 调试控制
// ============================================================================
#define DEBUG_MODE 1

#if DEBUG_MODE
#ifdef _KERNEL_MODE
#define DBG_PRINT(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ShellcodeDetector] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...) printf("[ShellcodeDetector] " fmt, ##__VA_ARGS__)
#endif
#else
#define DBG_PRINT(fmt, ...) ((void)0)
#endif

// ============================================================================
// 驱动信息定义
// ============================================================================
#define DRIVER_NAME             L"ShellcodeDetector"
#define DEVICE_NAME             L"\\Device\\ShellcodeDetector"
#define LINK_NAME               L"\\DosDevices\\ShellcodeDetector"
#define LOG_FILE_PATH           L"\\??\\C:\\XMemGuard\\logs\\ShellcodeDetector.log"
#define LOG_DIR_PATH            L"\\??\\C:\\XMemGuard\\logs"

// 注入 DLL 路径（内核态 Kernel Manual Map 使用，Win32 路径格式，代码会自动加 \??\ 前缀）
#define INJECT_DLL_PATH_X64     L"C:\\XMemGuard\\InjectDll.dll"
#define INJECT_DLL_PATH_X86     L"C:\\XMemGuard\\InjectDll.dll"

// ============================================================================
// IOCTL 码定义
// ============================================================================
#define IOCTL_DEVICE_BASE       0x8000
#define IOCTL_FUNCTION_BASE     0x800

#define IOCTL_CODE(x) CTL_CODE(IOCTL_DEVICE_BASE, (IOCTL_FUNCTION_BASE + (x)), METHOD_BUFFERED, FILE_ANY_ACCESS)

// 异常上报：用户态Shellcode -> 驱动
#define IOCTL_EXCEPTION_REPORT          IOCTL_CODE(0x01)

// 查询内存页面信息
#define IOCTL_QUERY_MEMORY_INFO         IOCTL_CODE(0x02)

// 获取日志条目
#define IOCTL_GET_LOG_ENTRIES           IOCTL_CODE(0x03)

// 连接测试
#define IOCTL_TEST_CONNECTION           IOCTL_CODE(0x04)

// 模块隐藏：注入 DLL -> 驱动（L1-L4 全隐藏）
#define IOCTL_HIDE_MODULE               IOCTL_CODE(0x05)

// ============================================================================
// 池标签常量
// ============================================================================
#define MAX_STACK_DEPTH                 32
#define PROCESS_HASH_TABLE_SIZE         512
#define MAX_PROCESS_NODES               4096
#define MAX_MEMORY_REGIONS_PER_PROCESS  1024
#define SHELLCODE_BUFFER_SIZE           0x1000
#define POOL_TAG_COMMON                 'CmoC'
#define POOL_TAG_PROCESS                'corP'
#define POOL_TAG_MEMORY                 'meMM'
#define POOL_TAG_SHELLCODE              'lhCS'

// 页面保护标志 - 含执行位掩码
#define EXECUTE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// 当前进程句柄值
#ifdef _WIN64
#define CURRENT_PROCESS_HANDLE ((HANDLE)0xFFFFFFFFFFFFFFFFULL)
#else
#define CURRENT_PROCESS_HANDLE ((HANDLE)0xFFFFFFFFUL)
#endif

// ============================================================================
// 异常上报数据包 (Shellcode -> Driver)
// ============================================================================
#pragma pack(push, 8)
typedef struct _EXCEPTION_REPORT_PACKET {
    // 异常基本信息
    ULONG       ExceptionCode;          // 异常码 (应为 0xC0000005)
    ULONG       ExceptionFlags;         // 异常标志
    ULONG_PTR   ExceptionAddress;       // 异常发生地址
    ULONG_PTR   FaultAddress;           // 错误地址 (ExceptionInformation[1])
    ULONG_PTR   AccessType;             // 访问类型 (ExceptionInformation[0], 8=Execute)

    // 进程/线程信息
    ULONG       ProcessId;              // 进程ID
    ULONG       ThreadId;               // 线程ID

    // 寄存器信息 (用于恢复执行)
    ULONG_PTR   ContextRip;             // RIP
    ULONG_PTR   ContextRsp;             // RSP
    ULONG_PTR   ContextRbp;             // RBP
    ULONG_PTR   ContextFlags;           // EFLAGS

    // 时间戳
    LARGE_INTEGER Timestamp;

    // 保留字段
    ULONG_PTR   Reserved[4];

} EXCEPTION_REPORT_PACKET, * PEXCEPTION_REPORT_PACKET;
#pragma pack(pop)

// ============================================================================
// 异常处理响应 (Driver -> Shellcode)
// ============================================================================
#pragma pack(push, 8)
typedef struct _EXCEPTION_RESPONSE_PACKET {
    NTSTATUS    Status;                 // 处理状态
    ULONG       Action;                 // 动作: 0=继续执行, 1=终止进程, 2=传递给原始处理程序
    ULONG_PTR   NewProtection;          // 新的保护属性
    ULONG_PTR   Reserved[2];
} EXCEPTION_RESPONSE_PACKET, * PEXCEPTION_RESPONSE_PACKET;
#pragma pack(pop)

// 响应动作常量
#define EXCEPTION_ACTION_CONTINUE       0   // 继续执行 (权限已恢复)
#define EXCEPTION_ACTION_TERMINATE      1   // 终止进程
#define EXCEPTION_ACTION_PASSTHROUGH    2   // 传递给原始异常处理程序

// ============================================================================
// 日志条目结构
// ============================================================================
#pragma pack(push, 8)
typedef struct _SHELLCODE_LOG_ENTRY {
    LARGE_INTEGER   Timestamp;          // 时间戳
    ULONG           ProcessId;          // 进程ID
    ULONG           ThreadId;           // 线程ID
    ULONG_PTR       FaultAddress;       // 错误地址
    ULONG_PTR       BaseAddress;        // 内存区域基址
    SIZE_T          RegionSize;         // 内存区域大小
    ULONG           OriginalProtection; // 原始保护属性
    ULONG           InitiatorPid;       // 攻击者进程ID
    ULONG           StackDepth;         // 调用栈深度
    ULONG_PTR       StackTrace[MAX_STACK_DEPTH]; // 调用栈帧
    CHAR            ProcessName[16];    // 进程名
    CHAR            InitiatorName[16];  // 攻击者进程名
} SHELLCODE_LOG_ENTRY, * PSHELLCODE_LOG_ENTRY;
#pragma pack(pop)

// ============================================================================
// 受控内存区域信息
// ============================================================================
typedef struct _CONTROLLED_MEMORY_REGION {
    ULONG_PTR   BaseAddress;            // 基址
    SIZE_T      Size;                   // 大小
    ULONG       CurrentProtection;      // 当前保护属性 (去掉了执行位)
    ULONG       OriginalProtection;     // 原始保护属性
    ULONG       InitiatorPid;           // 攻击者进程ID
    ULONG       TargetPid;              // 目标进程ID
    BOOLEAN     IsDirty;                // 是否被写入
    LARGE_INTEGER CreateTime;           // 创建时间
} CONTROLLED_MEMORY_REGION, * PCONTROLLED_MEMORY_REGION;

// ============================================================================
// 页面保护属性辅助函数 (内联)
// ============================================================================

// 需要保留的标志位
#define PRESERVE_FLAGS (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)

// 检测是否含有执行权限
__forceinline BOOLEAN HasExecuteProtection(ULONG Protection)
{
    return (Protection & EXECUTE_FLAGS) != 0;
}

// 移除可执行权限
__forceinline ULONG RemoveExecuteProtection(ULONG Protection)
{
    ULONG flags = Protection & PRESERVE_FLAGS;
    ULONG base = Protection & ~PRESERVE_FLAGS;

    switch (base) {
    case PAGE_EXECUTE:              base = PAGE_READONLY; break;
    case PAGE_EXECUTE_READ:         base = PAGE_READONLY; break;
    case PAGE_EXECUTE_READWRITE:    base = PAGE_READWRITE; break;
    case PAGE_EXECUTE_WRITECOPY:    base = PAGE_WRITECOPY; break;
        // 不含执行位的保持不变
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        break;
    default:
        base = PAGE_READONLY; // 安全默认值
        break;
    }
    return base | flags;
}

// 添加可执行权限 (用于恢复)
__forceinline ULONG AddExecuteProtection(ULONG Protection)
{
    ULONG flags = Protection & PRESERVE_FLAGS;
    ULONG base = Protection & ~PRESERVE_FLAGS;

    switch (base) {
    case PAGE_NOACCESS:             base = PAGE_EXECUTE; break;
    case PAGE_READONLY:             base = PAGE_EXECUTE_READ; break;
    case PAGE_READWRITE:            base = PAGE_EXECUTE_READWRITE; break;
    case PAGE_WRITECOPY:            base = PAGE_EXECUTE_WRITECOPY; break;
        // 不含执行位的保持不变
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        base = PAGE_EXECUTE_READ; // 安全默认值
        break;
    }
    return base | flags;
}

// 页面保护转字符串 (调试用)
__forceinline const char* ProtectionToString(ULONG Protection)
{
    ULONG base = Protection & ~PRESERVE_FLAGS;
    switch (base) {
    case PAGE_NOACCESS:             return "---";
    case PAGE_READONLY:             return "R--";
    case PAGE_READWRITE:            return "RW-";
    case PAGE_WRITECOPY:            return "RC-";
    case PAGE_EXECUTE:              return "--X";
    case PAGE_EXECUTE_READ:         return "R-X";
    case PAGE_EXECUTE_READWRITE:    return "RWX";
    case PAGE_EXECUTE_WRITECOPY:    return "RCX";
    default:                        return "???";
    }
}

// ============================================================================
// 地址范围宏定义
// ============================================================================
#define IS_ADDRESS_IN_RANGE(addr, base, size) \
    (((ULONG_PTR)(addr) >= (ULONG_PTR)(base)) && \
     ((ULONG_PTR)(addr) < ((ULONG_PTR)(base) + (SIZE_T)(size))))

// 用户态地址范围 (x64)
#ifdef _WIN64
#define USER_ADDRESS_MIN    0x0000000000010000ULL
#define USER_ADDRESS_MAX    0x00007FFFFFFFFFFFULL
#else
#define USER_ADDRESS_MIN    0x00010000UL
#define USER_ADDRESS_MAX    0x7FFFFFFFUL
#endif

#define IS_USER_ADDRESS(addr) \
    (((ULONG_PTR)(addr) >= USER_ADDRESS_MIN) && ((ULONG_PTR)(addr) <= USER_ADDRESS_MAX))


// ============================================================================
// 模块隐藏请求 (InjectDll -> 驱动)
// ============================================================================
#pragma pack(push, 8)
typedef struct _HIDE_MODULE_REQUEST {
    ULONG       ProcessId;          // 目标进程ID
    ULONG_PTR   ModuleBase;         // 模块基址
    SIZE_T      ModuleSize;         // 模块大小（用于Ldr链表匹配和头擦除范围）
    BOOLEAN     IsWow64;            // 目标进程是否为WoW64(32位)进程
    ULONG_PTR   Reserved[2];
} HIDE_MODULE_REQUEST, * PHIDE_MODULE_REQUEST;
#pragma pack(pop)
// 64-bit: sizeof = 48 bytes

// 32-bit DLL 发送的版本 (ULONG_PTR/SIZE_T 均为 4 字节，pack(8) 下总大小 = 24 字节)
// 字段偏移与 32-bit 编译结果严格一致，内核用于解析 WoW64 DLL 发来的缓冲区
typedef struct _HIDE_MODULE_REQUEST_32 {
    ULONG       ProcessId;      // +0
    ULONG       ModuleBase;     // +4  (32-bit ULONG_PTR)
    ULONG       ModuleSize;     // +8  (32-bit SIZE_T)
    BOOLEAN     IsWow64;        // +12
    UCHAR       Pad[3];         // +13 (pack(8) padding)
    ULONG       Reserved[2];    // +16
} HIDE_MODULE_REQUEST_32, * PHIDE_MODULE_REQUEST_32;
// sizeof = 24 bytes

// ============================================================================
// 异常上报 32-bit 变体 (WoW64 InjectDll -> 驱动)
// 与 EXCEPTION_REPORT_PACKET 字段语义相同，ULONG_PTR 替换为 ULONG
// pack(8) 下：11×ULONG(44B) + 4B pad + LARGE_INTEGER(8B) + 4×ULONG(16B) = 72 字节
// ============================================================================
#pragma pack(push, 8)
typedef struct _EXCEPTION_REPORT_PACKET_32 {
    ULONG           ExceptionCode;      // +0
    ULONG           ExceptionFlags;     // +4
    ULONG           ExceptionAddress;   // +8  (32-bit ptr)
    ULONG           FaultAddress;       // +12 (32-bit ptr)
    ULONG           AccessType;         // +16 (32-bit: 0=Read,1=Write,8=Execute)
    ULONG           ProcessId;          // +20
    ULONG           ThreadId;           // +24
    ULONG           ContextEip;         // +28 (x86 EIP)
    ULONG           ContextEsp;         // +32
    ULONG           ContextEbp;         // +36
    ULONG           ContextFlags;       // +40 (EFLAGS)
    // pad 4 bytes → LARGE_INTEGER 8-byte aligned at +48
    LARGE_INTEGER   Timestamp;          // +48
    ULONG           Reserved[4];        // +56
} EXCEPTION_REPORT_PACKET_32, * PEXCEPTION_REPORT_PACKET_32;
#pragma pack(pop)
// sizeof = 72 bytes

// 32-bit DLL 响应结构 (驱动 -> WoW64 InjectDll)
// ULONG_PTR → ULONG，sizeof = 20 字节
typedef struct _EXCEPTION_RESPONSE_PACKET_32 {
    NTSTATUS    Status;
    ULONG       Action;
    ULONG       NewProtection;
    ULONG       Reserved[2];
} EXCEPTION_RESPONSE_PACKET_32, * PEXCEPTION_RESPONSE_PACKET_32;
// sizeof = 20 bytes
