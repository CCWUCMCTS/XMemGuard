// ============================================================================
// DllMain.cpp - InjectDll 入口点
//
// 由内核手动映射本 DLL，并通过 ZwCreateThreadEx 启动初始化入口。
// DLL_PROCESS_ATTACH 中：
//   1. 初始化文件日志
//   2. 打开驱动设备句柄
//   3. 安装 KiUserExceptionDispatcher Hook
//   4. 请求内核执行 L1-L4 自隐藏
// DLL_PROCESS_DETACH 中执行反向清理。
// ============================================================================

#include <windows.h>
#include "../include/Logger.hpp"
#include "../include/DriverComm.hpp"
#include "../include/KiDispatchHook.hpp"
#include "../include/SelfHide.hpp"

// ============================================================================
// DllMain
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason) {

    case DLL_PROCESS_ATTACH:
        // OutputDebugStringA 是纯 Win32 API，不依赖 CRT，可在 DllMain 最早阶段使用
        // DbgView 需勾选 "Capture Win32" 才能看到这些输出
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: entry\n");

        // 1. 初始化日志（最先初始化，后续步骤均依赖日志）
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: calling Logger_Initialize\n");
        if (!Logger_Initialize()) {
            OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: Logger_Initialize failed (non-fatal)\n");
        }
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: Logger_Initialize done\n");

        Logger_Write("EVENT=INIT Step=DllLoaded PID=%lu", (unsigned long)GetCurrentProcessId());

        // 2. 打开驱动设备句柄
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: calling DriverComm_Initialize\n");
        if (!DriverComm_Initialize()) {
            Logger_Write("EVENT=INIT Step=DriverComm Result=FAIL");
            OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: DriverComm_Initialize failed\n");
            // 非致命——Hook 仍可安装，只是不能上报异常
        }
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: DriverComm_Initialize done\n");

        // 3. 安装 KiUserExceptionDispatcher Hook
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: calling KiDispatchHook_Install\n");
        if (!KiDispatchHook_Install()) {
            Logger_Write("EVENT=INIT Step=HookInstall Result=FAIL");
            OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: KiDispatchHook_Install FAILED\n");
            DriverComm_Cleanup();
            Logger_Cleanup();
            return FALSE;  // 初始化失败；手动映射调用方不据此自动卸载 DLL。
        }
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: KiDispatchHook_Install done\n");

        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: exception hook installed\n");

        // 4. 请求内核 L1-L4 自隐藏
        //    隐藏失败不阻止 Hook 工作，仅记录警告
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: calling SelfHide_RequestHide\n");
        if (!SelfHide_RequestHide(hinstDLL)) {
            Logger_Write("EVENT=INIT Step=SelfHide Result=FAIL");
            OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: SelfHide_RequestHide failed\n");
        }

        Logger_Write("EVENT=INIT Step=Complete Result=OK");
        OutputDebugStringA("[InjectDll] DLL_PROCESS_ATTACH: complete\n");
        break;

    case DLL_PROCESS_DETACH:
        Logger_Write("EVENT=CLEANUP Step=ProcessDetach");

        // 清理顺序与初始化相反
        KiDispatchHook_Remove();
        DriverComm_Cleanup();
        Logger_Cleanup();
        break;
    }

    return TRUE;
}
