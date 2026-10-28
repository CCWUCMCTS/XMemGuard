// ============================================================================
// DriverComm.cpp - 与内核驱动 ShellcodeDetector 通信实现
// 设备路径: \\.\ShellcodeDetector
// ============================================================================

#include "../include/DriverComm.hpp"
#include "../include/Logger.hpp"

// ============================================================================
// 全局状态
// ============================================================================

static HANDLE g_DeviceHandle = INVALID_HANDLE_VALUE;

// ============================================================================
// DriverComm_Initialize
// ============================================================================

BOOL DriverComm_Initialize(void)
{
    if (g_DeviceHandle != INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    // 打开驱动设备
    g_DeviceHandle = CreateFileW(
        L"\\\\.\\ShellcodeDetector",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_DeviceHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Logger_Write("EVENT=INIT Step=DriverComm Result=FAIL Error=0x%08lX", (unsigned long)err);
        return FALSE;
    }

    Logger_Write("EVENT=INIT Step=DriverComm Result=OK");
    return TRUE;
}

// ============================================================================
// DriverComm_Cleanup
// ============================================================================

void DriverComm_Cleanup(void)
{
    if (g_DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_DeviceHandle);
        g_DeviceHandle = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// DriverComm_ReportException
// 上报访问违例，返回驱动决策（继续/终止/传递）
// ============================================================================

BOOL DriverComm_ReportException(
    PEXCEPTION_REPORT_PACKET   Report,
    PEXCEPTION_RESPONSE_PACKET Response
)
{
    if (g_DeviceHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // 用 QueryPerformanceCounter 的原始计数填充时间戳（未换算单位）
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    Report->Timestamp.QuadPart = qpc.QuadPart;

    // 填充当前进程/线程 ID
    Report->ProcessId = GetCurrentProcessId();
    Report->ThreadId  = GetCurrentThreadId();

    OutputDebugStringA("[DriverComm] sending IOCTL_EXCEPTION_REPORT\n");

    DWORD bytesReturned = 0;
    BOOL  ok = DeviceIoControl(
        g_DeviceHandle,
        IOCTL_EXCEPTION_REPORT,
        Report,  sizeof(EXCEPTION_REPORT_PACKET),
        Response, sizeof(EXCEPTION_RESPONSE_PACKET),
        &bytesReturned,
        NULL
    );

    if (!ok) {
        DWORD err = GetLastError();
        OutputDebugStringA("[DriverComm] IOCTL_EXCEPTION_REPORT failed\n");
        Logger_Write("EVENT=IOCTL_FAIL IOCTL=EXCEPTION_REPORT Error=0x%08lX", (unsigned long)err);
        return FALSE;
    }

    OutputDebugStringA("[DriverComm] IOCTL_EXCEPTION_REPORT ok\n");
    return TRUE;
}

// ============================================================================
// DriverComm_RequestHide
// 请求驱动对当前进程中指定模块执行 L1-L4 全隐藏
// ============================================================================

BOOL DriverComm_RequestHide(
    ULONG_PTR ModuleBase,
    SIZE_T    ModuleSize
)
{
    if (g_DeviceHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    HIDE_MODULE_REQUEST req = { 0 };
    req.ProcessId  = GetCurrentProcessId();
    req.ModuleBase = ModuleBase;
    req.ModuleSize = ModuleSize;

    // 判断当前是否在 WoW64 进程中
    // IsWow64Process 需要动态获取（/MT 静态链接时也可以直接引用）
    BOOL isWow64 = FALSE;
    typedef BOOL (WINAPI* PFN_IsWow64Process)(HANDLE, PBOOL);
    PFN_IsWow64Process pfn = (PFN_IsWow64Process)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (pfn) {
        pfn(GetCurrentProcess(), &isWow64);
    }
    req.IsWow64 = isWow64;

    DWORD bytesReturned = 0;
    BOOL  ok = DeviceIoControl(
        g_DeviceHandle,
        IOCTL_HIDE_MODULE,
        &req, sizeof(req),
        NULL, 0,
        &bytesReturned,
        NULL
    );

    if (!ok) {
        DWORD err = GetLastError();
        Logger_Write("EVENT=IOCTL_FAIL IOCTL=HIDE_MODULE Error=0x%08lX", (unsigned long)err);
        return FALSE;
    }

    Logger_Write("EVENT=HIDE_REQUEST ModuleBase=%016llX ModuleSize=%llX",
        (unsigned long long)ModuleBase, (unsigned long long)ModuleSize);
    return TRUE;
}
