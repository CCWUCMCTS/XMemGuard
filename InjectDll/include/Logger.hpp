#pragma once
// ============================================================================
// Logger.hpp - 用户态文件日志模块头文件
// 输出路径: Logger.cpp 中 INJECTDLL_LOG_DIR 下的 ShellcodeDetector_<进程名>_<PID>.log
// ============================================================================

#include <windows.h>

// ============================================================================
// 初始化与清理
// ============================================================================

// 初始化日志模块，打开/创建日志文件
// 日志路径: Logger.cpp 中 INJECTDLL_LOG_DIR 下的 ShellcodeDetector_<ExeName>_<PID>.log
BOOL Logger_Initialize(void);

// 关闭日志文件句柄，写入会话结束标记
void Logger_Cleanup(void);

// ============================================================================
// 日志写入接口
// ============================================================================

// 写入格式化文本行（自动添加时间前缀）
void Logger_Write(const char* Format, ...);

// 写入异常检测事件
void Logger_WriteExceptionEvent(
    ULONG_PTR FaultAddress,
    ULONG     ExceptionCode,
    ULONG_PTR ExceptionAddress,
    ULONG_PTR AccessType
);
