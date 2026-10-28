#pragma once
// ============================================================================
// IoControl.hpp - IOCTL处理模块
// 处理驱动与用户态应用程序之间的通信
// ============================================================================

#include <ntifs.h>
#include "Common.hpp"

// ============================================================================
// IOCTL处理函数
// ============================================================================

// 处理IOCTL请求的主分发函数
NTSTATUS IoControl_DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

// 处理Create请求
NTSTATUS IoControl_DispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

// 处理Close请求
NTSTATUS IoControl_DispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

// 处理Read请求 (用于读取日志)
NTSTATUS IoControl_DispatchRead(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

// 默认分发函数
NTSTATUS IoControl_DispatchDefault(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

// ============================================================================
// 具体IOCTL处理函数
// ============================================================================

// 处理异常报告 (来自用户态Shellcode)
NTSTATUS IoControl_HandleExceptionReport(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

// 查询内存信息
NTSTATUS IoControl_HandleQueryMemoryInfo(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

// 获取日志条目
NTSTATUS IoControl_HandleGetLogEntries(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

// 测试连接
NTSTATUS IoControl_HandleTestConnection(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

// 处理模块隐藏请求
NTSTATUS IoControl_HandleHideModule(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PULONG BytesReturned
);
