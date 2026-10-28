// ============================================================================
// KiDispatchHook.cpp - KiUserExceptionDispatcher Hook 实现
//
// 安装流程：
//   1. 在 ntdll.dll 中找到 KiUserExceptionDispatcher 地址
//   2. 保存原始字节（x64 为 18 字节，供卸载时恢复使用）
//   3. 从 KiUED + ABS_JMP_SIZE（x64 为 18 字节）开始扫描，定位 RtlDispatchException（非公开导出，通过第一个 CALL 找到）
//   4. 用绝对间接跳转（FF 25 ... addr）覆写函数头部，跳转到本 DLL 的处理函数
//
// 拦截条件：
//   ExceptionCode == 0xC0000005 (ACCESS_VIOLATION)
//   ExceptionInformation[0] == 8 (Execute violation)
// ============================================================================

#include "../include/KiDispatchHook.hpp"
#include "../include/DriverComm.hpp"
#include "../include/Logger.hpp"
#include <winternl.h>
#include <intrin.h>

// ============================================================================
// 常量
// ============================================================================

// HookHandler 探针日志路径（修改此处即可统一调整）
#define HOOK_PROBE_LOG_PATH     "C:\\ShellcodeDetector_hook.log"

#ifdef _WIN64
// x64: KiUED 由内核 IRETQ 进入，RSP 在入口是 16 字节对齐（0 mod 16），
// 而 MSVC 编译的函数假设入口 RSP = 8 mod 16（CALL 压了返回地址）。
// 在 FF 25 前插入 sub rsp, 8（48 83 EC 08，4 字节），
// 使 HookHandler 入口 RSP = 8 mod 16，与普通 CALL 一致。
//
// 布局（18 字节）：
//   [0..3]  48 83 EC 08       sub rsp, 8
//   [4..9]  FF 25 00 00 00 00 jmp [RIP+0]  ; RIP 指向 byte10
//   [10..17] 8 字节           HookHandler 绝对地址
#define ABS_JMP_SIZE    18
#else
// x86: KiUED 入口 ESP 指向 [PEXCEPTION_RECORD, PCONTEXT]（无返回地址）。
// MSVC 编译的函数 prologue 假设 [ESP] = 返回地址, [ESP+4] = 参数1...
// sub esp, 4 预留"返回地址"空间，使参数自动对齐。
//
// 布局（8 字节）：
//   [0..2]  83 EC 04          sub esp, 4
//   [3..7]  E9 xx xx xx xx    jmp rel32 (HookHandler)
#define ABS_JMP_SIZE    8
#endif

#ifdef _WIN64
// ============================================================================
// 内部：查询 ProcessUserShadowStackPolicy 的最低位（x64 only）。
// 查询失败或接口不可用时返回 FALSE。
// ============================================================================
static BOOL IsCETActive(void)
{
    // 运行时查找 GetProcessMitigationPolicy，优先查询 kernelbase.dll，
    // 回退到 kernel32.dll。
    typedef BOOL (WINAPI* PFN_GPMP)(HANDLE, DWORD, PVOID, SIZE_T);

    HMODULE hMod = GetModuleHandleW(L"kernelbase.dll");
    if (!hMod) hMod = GetModuleHandleW(L"kernel32.dll");
    if (!hMod) return FALSE;

    PFN_GPMP pfn = (PFN_GPMP)GetProcAddress(hMod, "GetProcessMitigationPolicy");
    if (!pfn) {
        // 接口不可用时返回 FALSE。
        return FALSE;
    }

    // ProcessUserShadowStackPolicy = 38
    // PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY 只需读第一个 DWORD
    DWORD policyData = 0;
    if (!pfn(GetCurrentProcess(), 38, &policyData, sizeof(policyData))) {
        return FALSE;
    }
    // 返回 policyData 的最低位。
    return (policyData & 0x1) != 0;
}
#endif // _WIN64

// ============================================================================
// 全局状态
// ============================================================================

static BOOL    g_HookInstalled    = FALSE;
static PVOID   g_KiUserDispatcher = NULL;       // KiUserExceptionDispatcher 原始地址
static UCHAR   g_OriginalBytes[ABS_JMP_SIZE];   // 保存的原始字节（用于卸载恢复）
static UCHAR   g_HookJmpCode[ABS_JMP_SIZE];     // 写入的 JMP 字节（用于 passThrough 降级路径重装）
static PVOID   g_TrampolineBase   = NULL;

// HookHandler 中使用的函数指针——在 Install 时提前解析，
// 避免在 KiUED 异常上下文中触发 MSVC /MT 静态局部变量的 CRT 初始化锁。
// 注意：RtlDispatchException 不是公开导出，GetProcAddress 返回 NULL；
//       需通过扫描 KiUED+ABS_JMP_SIZE 之后代码的第一个 CALL 指令定位。
typedef NTSTATUS (NTAPI* PFN_NtContinue) (PCONTEXT, BOOL);
typedef BOOL     (NTAPI* PFN_RtlDE)      (PEXCEPTION_RECORD, PCONTEXT);
typedef NTSTATUS (NTAPI* PFN_NRE)        (PEXCEPTION_RECORD, PCONTEXT, BOOL);

static PFN_NtContinue g_pfnNtContinue = NULL;
static PFN_RtlDE      g_pfnRtlDE      = NULL;  // RtlDispatchException（扫描定位）
static PFN_NRE        g_pfnNRE        = NULL;

// ntdll._snprintf：替代 USER32.dll 的 wsprintfA，避免目标进程未加载 USER32 时
// IAT 未解析导致 HookHandler 内部调用 NULL 指针崩溃（console 进程不加载 USER32）。
typedef int (__cdecl* PFN_ntdll_snprintf)(char*, size_t, const char*, ...);
static PFN_ntdll_snprintf g_pfn_snprintf = NULL;

// 诊断计数器：HookHandler 被调用的次数（InterlockedIncrement 原子操作）
static volatile LONG g_HookEntryCount = 0;

// 诊断专用探针文件句柄：在 Install 时打开，HookHandler 用 WriteFile 直接写入，
// 不经过 Logger 的 CRITICAL_SECTION，是最可靠的"HookHandler 是否被进入"探针。
static HANDLE g_HookProbeFile = INVALID_HANDLE_VALUE;

#ifdef _WIN64
// x64: KiUED 入口 RSP 指向 CONTEXT 结构（由内核 IRETQ 设置），
// EXCEPTION_RECORD 位于 CONTEXT 之后，偏移量通过扫描 KiUED 原始代码确定。
static ULONG g_ExcRecordOffsetFromRSP = 0;
#endif

// ============================================================================
// 内部：HookHandler 专用原始日志
//
// 只使用 kernel32.dll 的 OutputDebugStringA / WriteFile，
// 完全不调用 CRT 函数（_vsnprintf_s 等访问 TLS 或需要 CRT 初始化的路径），
// 避免在 KiUED 异常分发上下文中触发嵌套异常。
// ============================================================================
static void HookRawLog(const char* msg)
{
    OutputDebugStringA(msg);
    if (g_HookProbeFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_HookProbeFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
        WriteFile(g_HookProbeFile, "\r\n", 2, &written, NULL);
    }
}

// ============================================================================
// 前向声明
// ============================================================================

// HookHandler 使用 dllexport；工程另配置 /EXPORT:HookHandlerExport。
__declspec(dllexport) VOID NTAPI HookHandler(PEXCEPTION_RECORD ExcRecord, PCONTEXT Context);

// 链接器导出别名
extern "C" __declspec(dllexport)
VOID NTAPI HookHandlerExport(PEXCEPTION_RECORD ExcRecord, PCONTEXT Context)
{
    HookHandler(ExcRecord, Context);
}

// ============================================================================
// 内部：从 ntdll 找到目标函数地址
// ============================================================================

static PVOID GetKiUserExceptionDispatcher(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return NULL;
    return GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
}

// ============================================================================
// 内部：VirtualProtect + 写内存辅助
// ============================================================================

static BOOL WriteProtectedMemory(PVOID Dest, const VOID* Src, SIZE_T Size)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(Dest, Size, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return FALSE;
    }
    memcpy(Dest, Src, Size);
    VirtualProtect(Dest, Size, oldProt, &oldProt);
    return TRUE;
}

// ============================================================================
// 内部：扫描 KiUED+ABS_JMP_SIZE 以后的代码，找第一个目标在 ntdll 范围内的
//       CALL rel32 指令——即 RtlDispatchException
// ============================================================================

static PFN_RtlDE ScanForRtlDispatchException(PVOID KiUED, HMODULE hNtdll)
{
    if (!KiUED || !hNtdll) return NULL;

    // 获取 ntdll 地址范围
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PUCHAR)hNtdll + dos->e_lfanew);
    ULONG_PTR ntBase = (ULONG_PTR)hNtdll;
    ULONG_PTR ntEnd  = ntBase + nt->OptionalHeader.SizeOfImage;

    // 从 KiUED + ABS_JMP_SIZE（x64 为 18 字节，已覆盖范围之后）开始扫描，最多 512 字节
    PUCHAR scan = (PUCHAR)KiUED + ABS_JMP_SIZE;

    for (int i = 0; i < 512; i++) {
        if (scan[i] == 0xE8) {  // CALL rel32
            INT32     rel    = *(INT32*)(scan + i + 1);
            ULONG_PTR target = (ULONG_PTR)(scan + i + 5) + (ULONG_PTR)(LONG_PTR)rel;

            // 目标在 ntdll 范围内，且不是 KiUED 本身（避免递归自调用）
            if (target >= ntBase && target < ntEnd &&
                target != (ULONG_PTR)KiUED)
            {
                Logger_Write("[KiDispatchHook] 扫描到 RtlDispatchException: 0x%016llX (KiUED+%d)",
                    (unsigned long long)target, i + ABS_JMP_SIZE);
                return (PFN_RtlDE)target;
            }
        }
    }

    Logger_Write("[KiDispatchHook] 警告：未能扫描到 RtlDispatchException，passThrough 将使用降级路径");
    return NULL;
}

// ============================================================================
// KiDispatchHook_Install
// ============================================================================

BOOL KiDispatchHook_Install(void)
{
    if (g_HookInstalled) {
        return TRUE;
    }

    // 1. 找到 KiUserExceptionDispatcher
    g_KiUserDispatcher = GetKiUserExceptionDispatcher();
    if (!g_KiUserDispatcher) {
        Logger_Write("[KiDispatchHook] 无法找到 KiUserExceptionDispatcher");
        return FALSE;
    }
    Logger_Write("[KiDispatchHook] KiUserExceptionDispatcher = 0x%016llX",
        (unsigned long long)g_KiUserDispatcher);

    // 2. 读取并记录 KiUED 原始字节（覆写之前保存，供卸载时恢复使用）
    memcpy(g_OriginalBytes, g_KiUserDispatcher, ABS_JMP_SIZE);
    g_TrampolineBase = NULL;

    // 记录原始字节以便调试（后续若字节验证失败可对比）
    {
        PUCHAR p = g_OriginalBytes;
        Logger_Write("[KiDispatchHook] KiUED 原始字节: "
            "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            p[0],  p[1],  p[2],  p[3],  p[4],  p[5],  p[6],
            p[7],  p[8],  p[9],  p[10], p[11], p[12], p[13]);
    }

    // 3. 提前解析所有函数指针（避免在 KiUED 上下文中触发 MSVC /MT CRT 初始化锁）
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

        g_pfnNtContinue = (PFN_NtContinue) GetProcAddress(hNtdll, "NtContinue");
        g_pfnNRE        = (PFN_NRE)        GetProcAddress(hNtdll, "NtRaiseException");
        g_pfn_snprintf  = (PFN_ntdll_snprintf) GetProcAddress(hNtdll, "_snprintf");

        // RtlDispatchException 不是公开导出，通过扫描 KiUED 代码找到
        // 注意：此时 KiUED 原始字节仍在原处（尚未覆写），扫描从 KiUED+ABS_JMP_SIZE 之后开始
        g_pfnRtlDE = ScanForRtlDispatchException(g_KiUserDispatcher, hNtdll);

        Logger_Write("[KiDispatchHook] 函数指针: NtContinue=%p RtlDE=%p NtRaiseException=%p _snprintf=%p",
            (void*)g_pfnNtContinue, (void*)g_pfnRtlDE, (void*)g_pfnNRE, (void*)g_pfn_snprintf);
    }

#ifdef _WIN64
    // 3b. (x64 only) 扫描 KiUED 代码确定 EXCEPTION_RECORD 相对于 RSP 的偏移量
    //     KiUED 入口 RSP 指向 CONTEXT，EXCEPTION_RECORD 在其后某偏移处。
    //     KiUED 在调用 RtlDispatchException 之前用 LEA RCX, [RSP+offset] 计算该地址。
    //     我们扫描原始代码找到这条 LEA 指令来确定偏移量。
    {
        PUCHAR scan = (PUCHAR)g_KiUserDispatcher;

        // 转储 KiUED+18..+49 字节用于诊断（这些字节不会被 Hook 覆写）
        Logger_Write("[KiDispatchHook] KiUED bytes [18..49]: "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X",
            scan[18], scan[19], scan[20], scan[21], scan[22], scan[23], scan[24], scan[25],
            scan[26], scan[27], scan[28], scan[29], scan[30], scan[31], scan[32], scan[33],
            scan[34], scan[35], scan[36], scan[37], scan[38], scan[39], scan[40], scan[41],
            scan[42], scan[43], scan[44], scan[45], scan[46], scan[47], scan[48], scan[49]);

        // 模式1: LEA RCX, [RSP + disp32]: 48 8D 8C 24 xx xx xx xx
        // 模式2: LEA RCX, [RSP + disp8]:  48 8D 4C 24 xx
        // 模式3: ADD RCX, imm32:          48 81 C1 xx xx xx xx（前有 MOV RCX, RSP）
        //        Win10 22H2 使用模式3: mov rcx, rsp; add rcx, 0x4F0
        for (int i = 0; i < 60 && g_ExcRecordOffsetFromRSP == 0; i++) {
            // 模式1: LEA RCX, [RSP + disp32]
            if (scan[i] == 0x48 && scan[i+1] == 0x8D && scan[i+2] == 0x8C && scan[i+3] == 0x24) {
                g_ExcRecordOffsetFromRSP = *(ULONG*)(scan + i + 4);
                Logger_Write("[KiDispatchHook] Found LEA RCX,[RSP+0x%lX] at KiUED+%d",
                    (unsigned long)g_ExcRecordOffsetFromRSP, i);
                break;
            }
            // 模式2: LEA RCX, [RSP + disp8]
            if (scan[i] == 0x48 && scan[i+1] == 0x8D && scan[i+2] == 0x4C && scan[i+3] == 0x24) {
                g_ExcRecordOffsetFromRSP = (ULONG)(UCHAR)scan[i+4];
                Logger_Write("[KiDispatchHook] Found LEA RCX,[RSP+0x%lX] at KiUED+%d",
                    (unsigned long)g_ExcRecordOffsetFromRSP, i);
                break;
            }
            // 模式3: ADD RCX, imm32 (48 81 C1 xx xx xx xx)
            // 仅在前面有 MOV RCX, RSP (48 8B CC) 时匹配
            if (i >= 3 && scan[i] == 0x48 && scan[i+1] == 0x81 && scan[i+2] == 0xC1) {
                // 回溯检查前面是否有 MOV RCX, RSP (48 8B CC)
                if (scan[i-3] == 0x48 && scan[i-2] == 0x8B && scan[i-1] == 0xCC) {
                    g_ExcRecordOffsetFromRSP = *(ULONG*)(scan + i + 3);
                    Logger_Write("[KiDispatchHook] Found MOV RCX,RSP + ADD RCX,0x%lX at KiUED+%d",
                        (unsigned long)g_ExcRecordOffsetFromRSP, i - 3);
                    break;
                }
            }
        }

        if (g_ExcRecordOffsetFromRSP == 0) {
            g_ExcRecordOffsetFromRSP = 0x4F0;
            Logger_Write("[KiDispatchHook] 警告：未找到偏移指令，使用默认偏移 0x4F0");
        }
    }
#else
    // 3b. (x86) KiUED 入口栈布局：[ESP] = PEXCEPTION_RECORD, [ESP+4] = PCONTEXT
    //     使用 sub esp,4 + jmp 方式 Hook 后，参数自动对齐到 MSVC 预期的位置，
    //     无需额外的偏移扫描。
    Logger_Write("[KiDispatchHook] x86 模式：参数直接从栈获取，跳过偏移扫描");
#endif

    // 3c. 打开 HookHandler 专用探针日志文件（CreateFile：kernel32，无 CRT 依赖）
    //     WriteFile 在 HookHandler 内部安全，不经过 Logger 的 CRITICAL_SECTION
    if (g_HookProbeFile == INVALID_HANDLE_VALUE) {
        g_HookProbeFile = CreateFileA(
            HOOK_PROBE_LOG_PATH,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            NULL);
        if (g_HookProbeFile == INVALID_HANDLE_VALUE) {
            Logger_Write("[KiDispatchHook] 警告：无法创建探针日志文件，将仅用 DbgView 诊断");
        } else {
            Logger_Write("[KiDispatchHook] 探针日志文件已打开: C:\\ShellcodeDetector_hook.log");
        }
    }

    // 4. 构造并写入 JMP 跳转指令，跳转到 HookHandler
    {
#ifdef _WIN64
        // x64 布局（18 字节）：
        //   [0..3]  48 83 EC 08       sub rsp, 8    <- 补齐 CALL 压栈，修正 RSP 对齐
        //   [4..9]  FF 25 00 00 00 00 jmp [RIP+0]   <- RIP 在 FF25 后 = byte 10
        //   [10..17] HookHandler 绝对地址
        ULONG_PTR hookAddr = (ULONG_PTR)HookHandler;

        // sub rsp, 8：48 83 EC 08
        g_HookJmpCode[0] = 0x48; g_HookJmpCode[1] = 0x83;
        g_HookJmpCode[2] = 0xEC; g_HookJmpCode[3] = 0x08;
        // jmp [RIP+0]：FF 25 00 00 00 00
        g_HookJmpCode[4] = 0xFF; g_HookJmpCode[5] = 0x25;
        g_HookJmpCode[6] = 0x00; g_HookJmpCode[7] = 0x00;
        g_HookJmpCode[8] = 0x00; g_HookJmpCode[9] = 0x00;
        // 8 字节地址（RIP+0 = byte 10）
        *(ULONG_PTR*)(g_HookJmpCode + 10) = hookAddr;

        Logger_Write("[KiDispatchHook] 写入 JMP (x64): HookHandler=0x%016llX",
            (unsigned long long)hookAddr);
#else
        // x86 布局（8 字节）：
        //   [0..2]  83 EC 04          sub esp, 4    <- 预留"返回地址"空间
        //   [3..7]  E9 xx xx xx xx    jmp rel32     <- 跳转到 HookHandler
        ULONG_PTR hookAddr = (ULONG_PTR)HookHandler;
        ULONG_PTR jmpFrom = (ULONG_PTR)g_KiUserDispatcher + 8;  // jmp 指令结束位置
        LONG rel32 = (LONG)(hookAddr - jmpFrom);

        // sub esp, 4：83 EC 04
        g_HookJmpCode[0] = 0x83; g_HookJmpCode[1] = 0xEC; g_HookJmpCode[2] = 0x04;
        // jmp rel32：E9 xx xx xx xx
        g_HookJmpCode[3] = 0xE9;
        *(LONG*)(g_HookJmpCode + 4) = rel32;

        Logger_Write("[KiDispatchHook] 写入 JMP (x86): HookHandler=0x%08lX rel32=0x%08lX",
            (unsigned long)hookAddr, (unsigned long)rel32);
#endif

        if (!WriteProtectedMemory(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE)) {
            Logger_Write("[KiDispatchHook] 写入跳转指令失败，错误=0x%08lX",
                (unsigned long)GetLastError());
            return FALSE;
        }

        // 保持 KiUED 页面永久 RWX，使 HookHandler 内部可通过简单 memcpy
        // 临时恢复/重装 Hook 字节（反递归保护），无需再调用 VirtualProtect。
        {
            DWORD keepProt;
            VirtualProtect(g_KiUserDispatcher, ABS_JMP_SIZE, PAGE_EXECUTE_READWRITE, &keepProt);
        }

        // 回读验证
        PUCHAR p = (PUCHAR)g_KiUserDispatcher;
#ifdef _WIN64
        Logger_Write("[KiDispatchHook] KiUED 字节验证 [0..9]: "
            "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X "
            "(期望 48 83 EC 08 FF 25 00 00 00 00)",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]);
        if (p[0] != 0x48 || p[4] != 0xFF || p[5] != 0x25) {
            Logger_Write("[KiDispatchHook] 警告：字节写入未生效（可能被 HVCI/VBS 拦截），Hook 无效");
            OutputDebugStringA("[KiDispatchHook] WARNING: KiUED bytes not modified - possible HVCI block\n");
        }
#else
        Logger_Write("[KiDispatchHook] KiUED 字节验证 [0..7]: "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "(期望 83 EC 04 E9 xx xx xx xx)",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        if (p[0] != 0x83 || p[1] != 0xEC || p[2] != 0x04 || p[3] != 0xE9) {
            Logger_Write("[KiDispatchHook] 警告：字节写入未生效，Hook 无效");
            OutputDebugStringA("[KiDispatchHook] WARNING: KiUED bytes not modified\n");
        }
#endif
    }

#ifdef _WIN64
    // -----------------------------------------------------------------------
    // x64 诊断：检查 HookHandler 入口字节是否为 F3 0F 1E FA。
    // -----------------------------------------------------------------------
    {
        PUCHAR h = (PUCHAR)(ULONG_PTR)HookHandler;
        BOOL hasEndbr64 = (h[0] == 0xF3 && h[1] == 0x0F && h[2] == 0x1E && h[3] == 0xFA);
        Logger_Write("[KiDispatchHook] HookHandler 入口字节: %02X %02X %02X %02X — %s",
            h[0], h[1], h[2], h[3],
            hasEndbr64 ? "endbr64 存在 (CET/IBT OK)"
                       : "!!! 缺少 endbr64 !!!");
        OutputDebugStringA(hasEndbr64
            ? "[KiDispatchHook] CET/IBT: endbr64 present - OK\n"
            : "[KiDispatchHook] CET/IBT: endbr64 MISSING\n");

        if (!hasEndbr64) {
            BOOL cetActive = IsCETActive();
            Logger_Write("[KiDispatchHook] CET/IBT 运行时状态: %s",
                cetActive ? "已启用（IBT 强制执行）" : "未启用（可跳过 endbr64 要求）");

            if (cetActive) {
                Logger_Write("[KiDispatchHook] CET 活跃但 endbr64 缺失，恢复 KiUED 原始字节后中止。"
                    "修复：vcxproj Release|x64 ClCompile 加 <ControlFlowGuard>Guard</ControlFlowGuard>"
                    " 并 Clean Rebuild。");
                WriteProtectedMemory(g_KiUserDispatcher, g_OriginalBytes, ABS_JMP_SIZE);
                return FALSE;
            } else {
                Logger_Write("[KiDispatchHook] CET 未活跃，跳过 endbr64 检查，继续安装");
            }
        }
    }
#endif

    g_HookInstalled = TRUE;
    Logger_Write("EVENT=HOOK_STATUS Status=INSTALLED KiUED=%p", g_KiUserDispatcher);
    return TRUE;
}

// ============================================================================
// KiDispatchHook_Remove
// ============================================================================

void KiDispatchHook_Remove(void)
{
    if (!g_HookInstalled || !g_KiUserDispatcher) return;

    WriteProtectedMemory(g_KiUserDispatcher, g_OriginalBytes, ABS_JMP_SIZE);
    g_TrampolineBase = NULL;

    g_HookInstalled = FALSE;
    Logger_Write("EVENT=HOOK_STATUS Status=REMOVED");

    if (g_HookProbeFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_HookProbeFile);
        g_HookProbeFile = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// KiDispatchHook_IsInstalled
// ============================================================================

BOOL KiDispatchHook_IsInstalled(void)
{
    return g_HookInstalled;
}

// ============================================================================
// HookHandler - KiUserExceptionDispatcher 替代处理函数
//
// 注意：RCX/RDX 是垃圾值！内核 IRETQ 进入 KiUED 时不设置 RCX/RDX，
//       只设置 RSP 指向 CONTEXT 结构。真实参数通过 _AddressOfReturnAddress()
//       从栈上恢复（见函数内部注释）。
//       此函数必须以 NtContinue / NtRaiseException / TerminateProcess 结束，
//       绝不能通过普通 ret 返回（否则弹出垃圾地址，立即崩溃）。
// ============================================================================

__declspec(dllexport) VOID NTAPI HookHandler(PEXCEPTION_RECORD ExcRecord, PCONTEXT Context)
{
    // =====================================================================
    // 反递归保护（最关键的第一步）：
    //
    // HookHandler 内部的任何函数调用（OutputDebugStringA、_snprintf、
    // RtlDispatchException 等）都可能触发二次异常。二次异常经过 KiUED
    // （此时仍被 Hook）→ 再次进入 HookHandler → 无限递归直到栈溢出。
    //
    // 解决方案：进入后立即恢复 KiUED 原始字节。此后，HookHandler 内部
    // 任何二次异常都走真正的 KiUED 原始代码，不会回到这里。
    // 在每个退出路径（NtContinue / NtRaiseException / TerminateProcess）
    // 前重新安装 Hook 字节。
    //
    // 前提：KiUED 所在页面在 Install 时已设为永久 RWX，
    //       此处 memcpy 不需要 VirtualProtect。
    // =====================================================================
    memcpy(g_KiUserDispatcher, g_OriginalBytes, ABS_JMP_SIZE);

    // =====================================================================
    // 从栈上恢复真实参数（关键！）
    // =====================================================================
#ifdef _WIN64
    // x64: 内核 IRETQ 进入 KiUED 时只设置 RSP（指向 CONTEXT 结构），
    // 不设置 RCX/RDX。参数 (RCX/RDX) 是线程异常前的残留值（垃圾）。
    //
    // _AddressOfReturnAddress() 返回编译器认为的"返回地址"槽位地址。
    // 由于我们通过 sub rsp,8 + jmp 进入（模拟了 CALL 压栈），
    // 该槽位 = RSP_original - 8，所以 RSP_original = 槽位地址 + 8。
    {
        ULONG_PTR originalRSP = (ULONG_PTR)_AddressOfReturnAddress() + 8;
        Context   = (PCONTEXT)originalRSP;
        ExcRecord = (PEXCEPTION_RECORD)(originalRSP + g_ExcRecordOffsetFromRSP);
    }
#else
    // x86: KiUED 入口 ESP 指向 [PEXCEPTION_RECORD, PCONTEXT]
    // 我们用 sub esp,4 + jmp 进入，MSVC prologue 后参数已正确对齐：
    //   ExcRecord = [EBP+8] = 第一个参数（原 [ESP]）
    //   Context   = [EBP+12] = 第二个参数（原 [ESP+4]）
    // 因此 x86 上 ExcRecord/Context 已经由编译器正确绑定，无需手动恢复。
    // 但要注意：x86 KiUED 的栈布局中 [ESP] 和 [ESP+4] 是指针，不是结构体本身。
    (void)0;  // 参数已由 MSVC 正确传递
#endif

    LONG entryCount = InterlockedIncrement(&g_HookEntryCount);

    // 诊断日志（此时安全——二次异常走原始 KiUED，不会递归）
    // 使用 ntdll._snprintf 替代 wsprintfA（USER32.dll 可能未加载）
    {
        char _logBuf[384];
        if (g_pfn_snprintf) {
            g_pfn_snprintf(_logBuf, sizeof(_logBuf),
                "[HookHandler] ENTRY #%ld pExc=0x%016I64X pCtx=0x%016I64X Code=0x%08lX Addr=0x%016I64X Info0=%I64u",
                (long)entryCount,
                (unsigned __int64)(ULONG_PTR)ExcRecord,
                (unsigned __int64)(ULONG_PTR)Context,
                ExcRecord ? (unsigned long)ExcRecord->ExceptionCode        : 0xDEADC0DE,
                ExcRecord ? (unsigned __int64)ExcRecord->ExceptionAddress  : 0,
                (ExcRecord && ExcRecord->NumberParameters > 0)
                    ? (unsigned __int64)ExcRecord->ExceptionInformation[0] : 0);
        } else {
            lstrcpyA(_logBuf, "[HookHandler] ENTRY (no _snprintf)");
        }
        HookRawLog(_logBuf);
    }

    // 空指针保护
    if (!ExcRecord || !Context) {
        HookRawLog("[HookHandler] NULL ExcRecord or Context — terminating (0xDEAD0001)");
        memcpy(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE);
        TerminateProcess(GetCurrentProcess(), 0xDEAD0001);
        return;
    }

    BOOL passThrough = TRUE;

    // 只处理执行型访问违例（AccessType == 8）
    if (ExcRecord->ExceptionCode == (DWORD)0xC0000005 &&
        ExcRecord->NumberParameters >= 2 &&
        ExcRecord->ExceptionInformation[0] == 8)
    {
        ULONG_PTR faultAddr = ExcRecord->ExceptionInformation[1];

        {
            char dbgBuf[128];
            if (g_pfn_snprintf)
                g_pfn_snprintf(dbgBuf, sizeof(dbgBuf), "[HookHandler] Execute violation at 0x%016I64X",
                    (unsigned __int64)faultAddr);
            else
                lstrcpyA(dbgBuf, "[HookHandler] Execute violation (no fmt)");
            HookRawLog(dbgBuf);
        }

        Logger_Write("EVENT=EXCEPTION_CAUGHT FaultAddr=%016llX",
            (unsigned long long)faultAddr);
        Logger_WriteExceptionEvent(
            faultAddr,
            ExcRecord->ExceptionCode,
            (ULONG_PTR)ExcRecord->ExceptionAddress,
            ExcRecord->ExceptionInformation[0]
        );

        // 构造上报包并发送给驱动
        EXCEPTION_REPORT_PACKET   report   = { 0 };
        EXCEPTION_RESPONSE_PACKET response = { 0 };

        report.ExceptionCode    = ExcRecord->ExceptionCode;
        report.ExceptionFlags   = ExcRecord->ExceptionFlags;
        report.ExceptionAddress = (ULONG_PTR)ExcRecord->ExceptionAddress;
        report.FaultAddress     = faultAddr;
        report.AccessType       = ExcRecord->ExceptionInformation[0];
#ifdef _WIN64
        report.ContextRip       = Context->Rip;
        report.ContextRsp       = Context->Rsp;
        report.ContextRbp       = Context->Rbp;
#else
        report.ContextRip       = Context->Eip;
        report.ContextRsp       = Context->Esp;
        report.ContextRbp       = Context->Ebp;
#endif
        report.ContextFlags     = Context->EFlags;

        HookRawLog("[HookHandler] calling DriverComm_ReportException");
        BOOL driverOk = DriverComm_ReportException(&report, &response);

        {
            char dbgBuf2[128];
            if (g_pfn_snprintf)
                g_pfn_snprintf(dbgBuf2, sizeof(dbgBuf2), "[HookHandler] DriverComm result=%d Action=%lu Status=0x%08lX",
                    (int)driverOk, driverOk ? (unsigned long)response.Action : 0xFFFF,
                    driverOk ? (unsigned long)response.Status : 0);
            else
                lstrcpyA(dbgBuf2, "[HookHandler] DriverComm done (no fmt)");
            HookRawLog(dbgBuf2);
        }

        if (driverOk) {
            if (response.Action == 0 /* CONTINUE */) {
                passThrough = FALSE;
                HookRawLog("[HookHandler] Action=CONTINUE, calling NtContinue");
                memcpy(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE);
                if (g_pfnNtContinue) {
                    g_pfnNtContinue(Context, FALSE);
                }
                HookRawLog("[HookHandler] NtContinue returned unexpectedly!");
                passThrough = TRUE;  // NtContinue 失败的降级
            }
            else if (response.Action == 1 /* TERMINATE */) {
                HookRawLog("[HookHandler] Action=TERMINATE");
                memcpy(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE);
                TerminateProcess(GetCurrentProcess(), (UINT)0xDEAD1234);
            }
            else {
                char dbgBuf3[64];
                if (g_pfn_snprintf)
                    g_pfn_snprintf(dbgBuf3, sizeof(dbgBuf3), "[HookHandler] Action=PASSTHROUGH (%lu)", (unsigned long)response.Action);
                else
                    lstrcpyA(dbgBuf3, "[HookHandler] Action=PASSTHROUGH");
                HookRawLog(dbgBuf3);
            }
        } else {
            HookRawLog("[HookHandler] DriverComm FAILED, falling to passThrough");
        }
    }

    if (passThrough) {
        // ----------------------------------------------------------------
        // passThrough：等价于原始 KiUED 的行为
        //   RtlDispatchException 在无 Hook 的 KiUED 下运行（已临时恢复），
        //   RtlDispatchException 内部触发的任何二次异常走真正的 KiUED，
        //   不会回到 HookHandler。
        //
        //   - 返回 TRUE  → VEH/SEH 已处理 → 重装 Hook → NtContinue
        //   - 返回 FALSE → 未处理 → 重装 Hook → NtRaiseException(FALSE)
        // ----------------------------------------------------------------
        if (g_pfnRtlDE) {
            HookRawLog("[HookHandler] passThrough: calling RtlDispatchException");
            BOOL handled = g_pfnRtlDE(ExcRecord, Context);

            // RtlDispatchException 已返回，重装 Hook
            memcpy(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE);

            if (handled) {
                HookRawLog("[HookHandler] passThrough: RtlDE=TRUE -> NtContinue");
                if (g_pfnNtContinue) {
                    g_pfnNtContinue(Context, FALSE);
                }
            } else {
                HookRawLog("[HookHandler] passThrough: RtlDE=FALSE -> NtRaiseException(FALSE)");
                if (g_pfnNRE) {
                    g_pfnNRE(ExcRecord, Context, FALSE);
                }
            }
        } else {
            memcpy(g_KiUserDispatcher, g_HookJmpCode, ABS_JMP_SIZE);
            HookRawLog("[HookHandler] passThrough: RtlDE=NULL, terminating");
        }

        HookRawLog("[HookHandler] passThrough: unexpected return, terminating (0xDEAD0002)");
        TerminateProcess(GetCurrentProcess(), 0xDEAD0002);
    }
}
