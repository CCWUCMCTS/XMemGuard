#pragma once
// ============================================================================
// DriverComm.hpp - 与内核驱动通信头文件
// 设备路径: \\.\ShellcodeDetector
// ============================================================================

#include <windows.h>

// 使用与内核侧相同的包结构（不包含内核头文件，手动定义）

// ============================================================================
// IOCTL 码（与 Common.hpp 保持一致）
// ============================================================================
#define IOCTL_DEVICE_BASE       0x8000
#define IOCTL_FUNCTION_BASE     0x800
#define IOCTL_CODE(x)           CTL_CODE(IOCTL_DEVICE_BASE, (IOCTL_FUNCTION_BASE + (x)), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_EXCEPTION_REPORT  IOCTL_CODE(0x01)
#define IOCTL_HIDE_MODULE       IOCTL_CODE(0x05)

// ============================================================================
// 与内核共享的数据包结构
// ============================================================================
#pragma pack(push, 8)

// 异常上报包（DLL -> 驱动）
typedef struct _EXCEPTION_REPORT_PACKET {
    ULONG       ExceptionCode;
    ULONG       ExceptionFlags;
    ULONG_PTR   ExceptionAddress;
    ULONG_PTR   FaultAddress;
    ULONG_PTR   AccessType;         // 8 = Execute violation
    ULONG       ProcessId;
    ULONG       ThreadId;
    ULONG_PTR   ContextRip;
    ULONG_PTR   ContextRsp;
    ULONG_PTR   ContextRbp;
    ULONG_PTR   ContextFlags;
    LARGE_INTEGER Timestamp;
    ULONG_PTR   Reserved[4];
} EXCEPTION_REPORT_PACKET, *PEXCEPTION_REPORT_PACKET;

// 异常响应包（驱动 -> DLL）
typedef struct _EXCEPTION_RESPONSE_PACKET {
    LONG        Status;
    ULONG       Action;             // 0=继续执行, 1=终止进程, 2=传递给原始处理
    ULONG_PTR   NewProtection;
    ULONG_PTR   Reserved[2];
} EXCEPTION_RESPONSE_PACKET, *PEXCEPTION_RESPONSE_PACKET;

// 模块隐藏请求（DLL -> 驱动）
typedef struct _HIDE_MODULE_REQUEST {
    ULONG       ProcessId;
    ULONG_PTR   ModuleBase;
    SIZE_T      ModuleSize;
    BOOL        IsWow64;
    ULONG_PTR   Reserved[2];
} HIDE_MODULE_REQUEST, *PHIDE_MODULE_REQUEST;

#pragma pack(pop)

// 响应 Action 值
#define EXCEPTION_ACTION_CONTINUE    0
#define EXCEPTION_ACTION_TERMINATE   1
#define EXCEPTION_ACTION_PASSTHROUGH 2

// ============================================================================
// 接口函数
// ============================================================================

// 打开驱动设备句柄（DllMain 中调用）
BOOL DriverComm_Initialize(void);

// 关闭驱动设备句柄
void DriverComm_Cleanup(void);

// 上报异常事件，返回驱动决策
BOOL DriverComm_ReportException(
    PEXCEPTION_REPORT_PACKET  Report,
    PEXCEPTION_RESPONSE_PACKET Response
);

// 请求驱动对本 DLL 执行 L1-L4 隐藏
BOOL DriverComm_RequestHide(
    ULONG_PTR ModuleBase,
    SIZE_T    ModuleSize
);
