#pragma once
// ============================================================================
// SelfHide.hpp - 请求内核对本 DLL 执行 L1-L4 隐藏
//
// L1: PEB64.Ldr 三链表摘除
// L2: MZ/PE 头覆零
// L3: VAD 节点标记为私有匿名内存
// L4: WoW64 进程同步摘除 PEB32.Ldr 条目
// ============================================================================

#include <windows.h>

// 获取本模块基址并通过 IOCTL_HIDE_MODULE 请求内核完成全隐藏
// 应在 DllMain(DLL_PROCESS_ATTACH) 的最后阶段调用
// hModule: DllMain 中的 hinstDLL（Kernel Manual Map 下 GetModuleHandleExW 无效，须显式传入）
BOOL SelfHide_RequestHide(HMODULE hModule);
