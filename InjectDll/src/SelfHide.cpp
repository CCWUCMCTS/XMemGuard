// ============================================================================
// SelfHide.cpp - 获取本模块信息并请求内核执行 L1-L4 隐藏
// ============================================================================

#include "../include/SelfHide.hpp"
#include "../include/DriverComm.hpp"
#include "../include/Logger.hpp"
#include <psapi.h>

// ============================================================================
// SelfHide_RequestHide
// ============================================================================

BOOL SelfHide_RequestHide(HMODULE hModule)
{
    // Kernel Manual Map 下 DLL 不在 PEB.Ldr，GetModuleHandleExW(FROM_ADDRESS) 必然失败。
    // 由调用方（DllMain）直接传入 hinstDLL（即映射基址）。
    HMODULE hSelf = hModule;
    if (!hSelf) {
        Logger_Write("[SelfHide] 模块基址为 NULL，跳过隐藏");
        return FALSE;
    }

    ULONG_PTR modBase = (ULONG_PTR)hSelf;

    // 通过 PE 头获取模块大小（SizeOfImage 字段）
    IMAGE_DOS_HEADER* dosHdr  = (IMAGE_DOS_HEADER*)modBase;
    IMAGE_NT_HEADERS* ntHdrs  = (IMAGE_NT_HEADERS*)(modBase + dosHdr->e_lfanew);
    SIZE_T            modSize = ntHdrs->OptionalHeader.SizeOfImage;

    Logger_Write("[SelfHide] 模块基址=0x%016llX 大小=0x%lX，发送隐藏请求",
        (unsigned long long)modBase, (unsigned long)modSize);

    return DriverComm_RequestHide(modBase, modSize);
}
