// ============================================================================
// Logger.cpp - 用户态文件日志实现
// 输出路径: INJECTDLL_LOG_DIR 下的 ShellcodeDetector_<进程名>_<PID>.log
// 使用 CRITICAL_SECTION 保护并发写入，每个进程独立文件，互不干扰
// ============================================================================

#include "../include/Logger.hpp"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// 日志输出目录（与内核驱动 LOG_DIR_PATH 一致）
// 部署前创建日志目录，并保证目标进程具有写入权限
// 修改此处即可统一调整所有 InjectDll 日志路径
#define INJECTDLL_LOG_DIR   "C:\\XMemGuard\\logs\\"

// ============================================================================
// 全局状态
// ============================================================================

static HANDLE            g_LogFile  = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION  g_LogLock;
static BOOL              g_Initialized = FALSE;

// ============================================================================
// 内部辅助：获取本地时间字符串
// ============================================================================

static void GetTimestampString(char* Buf, int BufSize)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf_s(Buf, BufSize, _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear, st.wMonth,  st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ============================================================================
// Logger_Initialize
// ============================================================================

BOOL Logger_Initialize(void)
{
    if (g_Initialized) {
        return TRUE;
    }

    // 检查日志目录是否存在
    {
        DWORD dirAttr = GetFileAttributesA(INJECTDLL_LOG_DIR);
        if (dirAttr == INVALID_FILE_ATTRIBUTES || !(dirAttr & FILE_ATTRIBUTE_DIRECTORY)) {
            OutputDebugStringA("[InjectDll] Logger: 日志目录不存在: " INJECTDLL_LOG_DIR "\n");
            OutputDebugStringA("[InjectDll] Logger: 请确认日志目录存在且目标进程具有写入权限\n");
            return FALSE;
        }
    }

    // 构造日志路径: INJECTDLL_LOG_DIR 下的 ShellcodeDetector_<ExeName>_<PID>.log
    char exeName[MAX_PATH] = "Unknown";
    GetModuleFileNameA(NULL, exeName, MAX_PATH);

    // 仅保留文件名部分（去掉路径和扩展名）
    char* lastName = exeName;
    for (char* p = exeName; *p; p++) {
        if (*p == '\\' || *p == '/') {
            lastName = p + 1;
        }
    }
    // 去掉扩展名
    char* dot = NULL;
    for (char* p = lastName; *p; p++) {
        if (*p == '.') dot = p;
    }
    if (dot) *dot = '\0';

    DWORD pid = GetCurrentProcessId();

    char logPath[MAX_PATH];
    _snprintf_s(logPath, sizeof(logPath), _TRUNCATE,
        INJECTDLL_LOG_DIR "ShellcodeDetector_%s_%lu.log", lastName, (unsigned long)pid);

    // 以追加方式打开/创建日志文件
    g_LogFile = CreateFileA(
        logPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_LogFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // 定位到文件末尾（追加写入）
    SetFilePointer(g_LogFile, 0, NULL, FILE_END);

    InitializeCriticalSection(&g_LogLock);
    g_Initialized = TRUE;

    // 写入会话开始标记
    Logger_Write("========== InjectDll 会话开始 | PID=%lu ==========", (unsigned long)pid);
    return TRUE;
}

// ============================================================================
// Logger_Cleanup
// ============================================================================

void Logger_Cleanup(void)
{
    if (!g_Initialized) return;

    Logger_Write("========== InjectDll 会话结束 ==========");

    CloseHandle(g_LogFile);
    g_LogFile = INVALID_HANDLE_VALUE;
    DeleteCriticalSection(&g_LogLock);
    g_Initialized = FALSE;
}

// ============================================================================
// Logger_Write
// ============================================================================

void Logger_Write(const char* Format, ...)
{
    if (!g_Initialized || g_LogFile == INVALID_HANDLE_VALUE) return;

    char timeBuf[32];
    GetTimestampString(timeBuf, sizeof(timeBuf));

    char msgBuf[1024];
    va_list args;
    va_start(args, Format);
    _vsnprintf_s(msgBuf, sizeof(msgBuf), _TRUNCATE, Format, args);
    va_end(args);

    char lineBuf[1200];
    int lineLen = _snprintf_s(lineBuf, sizeof(lineBuf), _TRUNCATE,
        "[%s] [U] %s\r\n", timeBuf, msgBuf);

    if (lineLen <= 0) return;

    EnterCriticalSection(&g_LogLock);

    DWORD written = 0;
    WriteFile(g_LogFile, lineBuf, (DWORD)lineLen, &written, NULL);

    LeaveCriticalSection(&g_LogLock);
}

// ============================================================================
// Logger_WriteExceptionEvent
// ============================================================================

void Logger_WriteExceptionEvent(
    ULONG_PTR FaultAddress,
    ULONG     ExceptionCode,
    ULONG_PTR ExceptionAddress,
    ULONG_PTR AccessType
)
{
    const char* accessStr = (AccessType == 8) ? "EXECUTE" :
                            (AccessType == 1) ? "WRITE" :
                            (AccessType == 0) ? "READ" : "UNKNOWN";
    Logger_Write(
        "EVENT=EXCEPTION Code=%08X FaultAddr=%016llX ExcAddr=%016llX AccessType=%s",
        (unsigned long)ExceptionCode,
        (unsigned long long)FaultAddress,
        (unsigned long long)ExceptionAddress,
        accessStr
    );
}
