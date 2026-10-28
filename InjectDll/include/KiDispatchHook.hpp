#pragma once
// ============================================================================
// KiDispatchHook.hpp - KiUserExceptionDispatcher Hook 头文件
//
// Hook 位于 KiUserExceptionDispatcher 入口，提供安装与卸载接口。
// 拦截 AccessType==8（Execute）的访问违例并上报内核驱动。
// ============================================================================

#include <windows.h>

// ============================================================================
// Hook 安装与卸载
// ============================================================================

// 在当前进程安装 KiUserExceptionDispatcher Hook
// 返回 TRUE 表示成功
BOOL KiDispatchHook_Install(void);

// 卸载 Hook，恢复原始字节
void KiDispatchHook_Remove(void);

// ============================================================================
// 状态查询
// ============================================================================

// 返回 Hook 是否已安装
BOOL KiDispatchHook_IsInstalled(void);
