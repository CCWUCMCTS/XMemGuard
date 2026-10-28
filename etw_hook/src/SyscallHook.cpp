// ============================================================================
// SyscallHook.cpp - 系统调用Hook实现
// 
// 注意：此实现依赖于ETW Hook基础设施
// 需要与现有的etwhook_init.hpp/etwhook_manager.hpp配合使用
// ============================================================================

#include "SyscallHook.hpp"
#include "Utils.hpp"
#include "DataManager.hpp"
#include "UserHookMgr.hpp"
#include "etwhook_manager.hpp"

#include "FileLogger.hpp"       // 权限变动文件日志

// ============================================================================
// 类型定义 - 系统调用原型
// ============================================================================

typedef NTSTATUS(*PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(*PFN_NtAllocateVirtualMemoryEx)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
    );

typedef NTSTATUS(*PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(*PFN_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(*PFN_NtMapViewOfSectionEx)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
    );

typedef NTSTATUS(*PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(*PFN_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

// ============================================================================
// 全局变量
// ============================================================================

static BOOLEAN g_SyscallHookInitialized = FALSE;
static BOOLEAN g_HooksEnabled[HookedSyscall_Max] = { FALSE };

// 原始函数指针
static PFN_NtAllocateVirtualMemory g_OrigNtAllocateVirtualMemory = NULL;
static PFN_NtAllocateVirtualMemoryEx g_OrigNtAllocateVirtualMemoryEx = NULL;
static PFN_NtProtectVirtualMemory g_OrigNtProtectVirtualMemory = NULL;
static PFN_NtMapViewOfSection g_OrigNtMapViewOfSection = NULL;
static PFN_NtMapViewOfSectionEx g_OrigNtMapViewOfSectionEx = NULL;
static PFN_NtWriteVirtualMemory g_OrigNtWriteVirtualMemory = NULL;
static PFN_NtQueryVirtualMemory g_OrigNtQueryVirtualMemory = NULL;

// 回调函数
static SYSCALL_PRE_CALLBACK g_PreCallback = NULL;
static SYSCALL_POST_CALLBACK g_PostCallback = NULL;

// ============================================================================
// 内部辅助函数
// ============================================================================

// 检查是否为远程进程操作
static BOOLEAN IsRemoteProcess(HANDLE ProcessHandle)
{
    return (ProcessHandle != NtCurrentProcess() &&
        ProcessHandle != CURRENT_PROCESS_HANDLE);
}

// ============================================================================
// KiUED Hook 保护
// ============================================================================

// 全局 KiUED 地址缓存（ntdll 在同一次启动中所有进程基址相同，KiUED 地址也相同）
static volatile PVOID g_KiUedAddress = NULL;

// 检查地址所在页是否与 KiUED 所在页重叠
static __forceinline BOOLEAN IsOverlappingKiUedPage(
    ULONG_PTR RegionStart,
    SIZE_T    RegionSize
)
{
    PVOID kiUed = g_KiUedAddress;
    if (!kiUed) return FALSE;
    ULONG_PTR kiUedPage = (ULONG_PTR)kiUed & ~(ULONG_PTR)0xFFF;  // 页对齐
    ULONG_PTR regionEnd = RegionStart + RegionSize;
    return (RegionStart <= kiUedPage + 0xFFF && regionEnd > kiUedPage);
}

// 检查目标进程是否已激活 KiUED Hook 保护（IOCTL_HIDE_MODULE 完成后才激活）
static BOOLEAN IsMonitoredProcess(HANDLE ProcessHandle, HANDLE* OutTargetPid)
{
    HANDLE targetPid = NULL;
    NTSTATUS status;

    if (!IsRemoteProcess(ProcessHandle)) {
        // 同进程：当前进程即为目标
        targetPid = PsGetCurrentProcessId();
    } else {
        status = Utils_GetPidFromHandle(ProcessHandle, &targetPid, NULL);
        if (!NT_SUCCESS(status)) return FALSE;
    }

    PPROCESS_NODE node = DataManager_FindProcess(targetPid);
    if (!node) return FALSE;
    BOOLEAN active = node->HookProtectionActive;
    DataManager_ReleaseProcess(node);

    if (active && OutTargetPid) {
        *OutTargetPid = targetPid;
    }
    return active;
}

// 将进程名安全地复制到调用方提供的 16 字节栈缓冲区。
//
// 背景：PsGetProcessImageFileName 返回的 PCHAR 指向 EPROCESS.ImageFileName 字段内部，
// 若持有该指针期间目标进程退出，指针可能失效。因此在调用方尽早拷贝到栈变量，
// 之后即便进程退出也不会访问已释放内存。
//
// 参数：
//   Pid     - 待查询进程的 PID（以 HANDLE 形式传入，与 PS API 一致）
//   OutName - 调用方在栈上预分配的 16 字节缓冲区（包含终止符）
static VOID CopyProcessName(_In_ HANDLE Pid, _Out_writes_(16) CHAR OutName[16])
{
    RtlZeroMemory(OutName, 16);
    PCHAR rawName = Utils_GetProcessNameByPid(Pid);
    if (rawName) {
        // EPROCESS.ImageFileName 最长 15 字节，手动限制拷贝长度
        SIZE_T len = 0;
        while (len < 15 && rawName[len] != '\0') { len++; }
        RtlCopyMemory(OutName, rawName, len);
        OutName[len] = '\0';
    }
}

// ============================================================================
// 进程名称白名单
// 父子关系且源名称在名单中，或双方名称均在名单中时豁免拦截。
// 其余跨进程可执行内存请求继续拦截。
// ============================================================================

static const char* g_ParentChildWhitelist[] = {
    // 系统核心服务（观测到大量合法 RWX 父子操作）
    "svchost.exe",          // → wermgr/StartMenu/dllhost 等
    "services.exe",         // 服务管理器
    "smss.exe",             // 会话管理器
    "csrss.exe",            // 客户端/服务器运行时

    // 浏览器多进程 JIT 架构
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2",       // PsGetProcessImageFileName 截断 msedgewebview2.exe 为 14 字符
    "firefox.exe",

    // .NET / Java 运行时
    "dotnet.exe",
    "w3wp.exe",             // IIS worker process
};

static BOOLEAN IsProcessWhitelisted(_In_ PCSTR ProcessName)
{
    for (int i = 0; i < ARRAYSIZE(g_ParentChildWhitelist); i++) {
        if (_stricmp(ProcessName, g_ParentChildWhitelist[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================================
// WHITELIST_SKIP 日志节流
// 同一 SrcPID+DstPID 组合只记录首次，避免 svchost 等高频操作撑爆日志。
// 固定大小环形缓冲区，无锁设计（最坏情况：竞态导致多记一条，可接受）。
// ============================================================================

#define WHITELIST_LOG_CACHE_SIZE 64

struct PidPair {
    ULONG SrcPid;
    ULONG DstPid;
};

static PidPair  g_WhitelistLogCache[WHITELIST_LOG_CACHE_SIZE] = {};
static volatile LONG g_WhitelistLogCacheCount = 0;

static BOOLEAN WhitelistLogSeen(ULONG SrcPid, ULONG DstPid)
{
    LONG count = g_WhitelistLogCacheCount;
    if (count > WHITELIST_LOG_CACHE_SIZE) count = WHITELIST_LOG_CACHE_SIZE;

    for (LONG i = 0; i < count; i++) {
        if (g_WhitelistLogCache[i].SrcPid == SrcPid &&
            g_WhitelistLogCache[i].DstPid == DstPid) {
            return TRUE;
        }
    }

    // 新组合，写入缓存（环形覆盖）
    LONG idx = InterlockedIncrement(&g_WhitelistLogCacheCount) - 1;
    idx = idx % WHITELIST_LOG_CACHE_SIZE;
    g_WhitelistLogCache[idx].SrcPid = SrcPid;
    g_WhitelistLogCache[idx].DstPid = DstPid;

    return FALSE;
}

// 检查是否应该拦截此操作
static BOOLEAN ShouldIntercept(
    HANDLE ProcessHandle,
    ULONG Protection,
    PHANDLE OutTargetPid,
    PLONGLONG OutCreateTime,
    _In_opt_ PCSTR SyscallName
)
{
    // 跳过当前进程
    if (!IsRemoteProcess(ProcessHandle)) {
        return FALSE;
    }

    // 检查是否有可执行权限
    if (!HasExecuteProtection(Protection)) {
        return FALSE;
    }

    // 获取目标PID
    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    NTSTATUS status = Utils_GetPidFromHandle(ProcessHandle, &targetPid, &createTime);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // 获取当前进程PID
    HANDLE currentPid = PsGetCurrentProcessId();

    // ================================================================
    // 自注入检测：SrcPID == DstPID
    // 恶意程序用 OpenProcess(own_pid) 而非 NtCurrentProcess() 分配 RWX，
    // IsRemoteProcess 因句柄值 != -1 而误判为远程操作。
    // 属于 T1620 反射式代码加载 / T1027.002 软件加壳，非 T1055 进程注入。
    // 仅记录事件，不拦截。
    // ================================================================
    if (currentPid == targetPid) {
        CHAR selfName[16], args[256];
        CopyProcessName(currentPid, selfName);
        _snprintf_s(args, sizeof(args), _TRUNCATE,
            "Syscall=%s PID=%lu Name=%s Protection=%s",
            SyscallName ? SyscallName : "?",
            (ULONG)(ULONG_PTR)currentPid, selfName,
            ProtectionToString(Protection));
        FileLogger_LogEvent("SELF_INJECT", args);
        return FALSE;
    }

    // 父子且源在白名单，或双方均在白名单时豁免拦截。
    BOOLEAN isParentChild = Utils_AreParentChildProcesses(currentPid, targetPid);
    CHAR srcName[16] = {};
    CHAR dstName[16] = {};
    CopyProcessName(currentPid, srcName);
    CopyProcessName(targetPid, dstName);
    BOOLEAN srcWhitelisted = IsProcessWhitelisted(srcName);
    BOOLEAN dstWhitelisted = IsProcessWhitelisted(dstName);
    BOOLEAN whitelistHit =
        (isParentChild && srcWhitelisted) ||
        (srcWhitelisted && dstWhitelisted);

    if (whitelistHit) {
        // 节流：同一 SrcPID+DstPID 只记录首次
        if (!WhitelistLogSeen((ULONG)(ULONG_PTR)currentPid,
                              (ULONG)(ULONG_PTR)targetPid)) {
            CHAR args[256];
            _snprintf_s(args, sizeof(args), _TRUNCATE,
                "Syscall=%s SrcPID=%lu SrcName=%s DstPID=%lu DstName=%s Protection=%s",
                SyscallName ? SyscallName : "?",
                (ULONG)(ULONG_PTR)currentPid, srcName,
                (ULONG)(ULONG_PTR)targetPid, dstName,
                ProtectionToString(Protection));
            FileLogger_LogEvent("WHITELIST_SKIP", args);
        }
        return FALSE;
    }

    if (isParentChild) {
        // 非白名单的父子操作：正常拦截（不再无条件跳过）
        DBG_PRINT("ShouldIntercept: 非白名单父子进程，正常拦截 %s %s(PID %lu) -> PID %lu\n",
            SyscallName ? SyscallName : "?",
            srcName,
            (ULONG)(ULONG_PTR)currentPid,
            (ULONG)(ULONG_PTR)targetPid);
    }

    if (OutTargetPid) {
        *OutTargetPid = targetPid;
    }
    if (OutCreateTime) {
        *OutCreateTime = createTime;
    }

    return TRUE;
}

// 记录操作并安装Hook
static VOID RecordAndInstallHook(
    HANDLE TargetPid,
    LONGLONG CreateTime,
    PVOID BaseAddress,
    SIZE_T Size,
    ULONG OriginalProtection,
    ULONG CurrentProtection
)
{
    HANDLE currentPid = PsGetCurrentProcessId();

    // 查找或创建进程节点
    BOOLEAN wasCreated = FALSE;
    PPROCESS_NODE processNode = DataManager_FindOrCreateProcess(
        TargetPid,
        CreateTime,
        &wasCreated
    );

    if (!processNode) {
        return;
    }

    // 添加内存区域记录
    DataManager_AddMemoryRegion(
        processNode,
        (ULONG_PTR)BaseAddress,
        Size,
        CurrentProtection,
        OriginalProtection,
        currentPid
    );

    // 如果是新进程，安装用户态Hook（HookPending 表示已确认目标进程未初始化，不再重试）
    if ((wasCreated || !processNode->IsHookInstalled) && !processNode->HookPending) {
        DBG_PRINT("SyscallHook: Installing user-mode hook for PID %lu\n",
            (ULONG)(ULONG_PTR)TargetPid);

        NTSTATUS status = UserHookMgr_InstallHook(TargetPid, CreateTime);

        if (!NT_SUCCESS(status)) {
            DBG_PRINT("SyscallHook: Failed to install hook (0x%08X)\n", status);

            // STATUS_NOT_FOUND = KiUED 解析失败（PEB->Ldr 未初始化）
            // 跨进程 RWX + Ldr 未初始化 = 疑似 Process Hollowing（向挂起进程注入可执行代码）
            if (status == STATUS_NOT_FOUND) {
                processNode->HookPending = TRUE;

                CHAR srcName[16], dstName[16], args[256];
                CopyProcessName(currentPid, srcName);
                CopyProcessName(TargetPid, dstName);

                DBG_PRINT("SyscallHook: 疑似 Process Hollowing - "
                    "PID %lu (%s) 向未初始化进程 PID %lu (%s) 注入可执行代码\n",
                    (ULONG)(ULONG_PTR)currentPid, srcName,
                    (ULONG)(ULONG_PTR)TargetPid, dstName);

                _snprintf_s(args, sizeof(args), _TRUNCATE,
                    "SrcPID=%lu SrcName=%s DstPID=%lu DstName=%s "
                    "Reason=PEB_LDR_NOT_INITIALIZED",
                    (ULONG)(ULONG_PTR)currentPid, srcName,
                    (ULONG)(ULONG_PTR)TargetPid, dstName);
                FileLogger_LogEvent("HOLLOWING_DETECTED", args);
            }

            // STATUS_NOT_SUPPORTED = WOW64 进程跳过（已由 UserHookMgr 输出 WOW64_SKIP 日志）
            // 不再重试，WOW64 状态不会改变
            if (status == STATUS_NOT_SUPPORTED) {
                processNode->HookPending = TRUE;
            }
        }
    }

    DataManager_ReleaseProcess(processNode);
}

// ============================================================================
// Detour函数实现
// ============================================================================

static NTSTATUS Detour_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
)
{
    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    // 检查是否需要拦截
    BOOLEAN shouldIntercept = ShouldIntercept(ProcessHandle, Protect, &targetPid, &createTime,
        "NtAllocateVirtualMemory");

    if (shouldIntercept) {
        // 修改保护属性，去除可执行位
        ULONG newProtect = RemoveExecuteProtection(Protect);

        DBG_PRINT("Detour_NtAllocateVirtualMemory: PID %lu -> %lu, Protection %s -> %s\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG)(ULONG_PTR)targetPid,
            ProtectionToString(Protect),
            ProtectionToString(newProtect));

        // 调用原始函数
        NTSTATUS status = g_OrigNtAllocateVirtualMemory(
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            newProtect
        );

        if (NT_SUCCESS(status) && BaseAddress && *BaseAddress && RegionSize && *RegionSize) {
            // 记录并安装Hook
            RecordAndInstallHook(
                targetPid,
                createTime,
                *BaseAddress,
                *RegionSize,
                Protect,
                newProtect
            );

            // -------------------------------------------------------
            // [FileLogger] 记录 NtAllocateVirtualMemory 权限降级事件
            // 在 syscall 成功、BaseAddress 已确定后记录
            // -------------------------------------------------------
            {
                CHAR _iName[16], _tName[16], _extra[64];
                CopyProcessName(PsGetCurrentProcessId(), _iName);
                CopyProcessName(targetPid, _tName);
                // AllocationType 包含 MEM_COMMIT(0x1000)/MEM_RESERVE(0x2000) 等标志位
                _snprintf_s(_extra, sizeof(_extra), _TRUNCATE,
                    "AllocType=0x%08X", AllocationType);
                FileLogger_LogProtectionChange(
                    "NtAllocateVirtualMemory",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _iName,
                    (ULONG)(ULONG_PTR)targetPid, _tName,
                    (ULONG_PTR)*BaseAddress, *RegionSize,
                    Protect, newProtect, status, _extra
                );
            }
        }

        return status;
    }

    // 正常调用
    return g_OrigNtAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}

static NTSTATUS Detour_NtAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
)
{
    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    BOOLEAN shouldIntercept = ShouldIntercept(ProcessHandle, PageProtection, &targetPid, &createTime,
        "NtAllocateVirtualMemoryEx");

    if (shouldIntercept) {
        ULONG newProtect = RemoveExecuteProtection(PageProtection);

        DBG_PRINT("Detour_NtAllocateVirtualMemoryEx: PID %lu -> %lu, Protection %s -> %s\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG)(ULONG_PTR)targetPid,
            ProtectionToString(PageProtection),
            ProtectionToString(newProtect));

        NTSTATUS status = g_OrigNtAllocateVirtualMemoryEx(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            AllocationType,
            newProtect,
            ExtendedParameters,
            ExtendedParameterCount
        );

        if (NT_SUCCESS(status) && BaseAddress && *BaseAddress && RegionSize && *RegionSize) {
            RecordAndInstallHook(
                targetPid,
                createTime,
                *BaseAddress,
                *RegionSize,
                PageProtection,
                newProtect
            );

            // -------------------------------------------------------
            // [FileLogger] 记录 NtAllocateVirtualMemoryEx 权限降级事件
            // -------------------------------------------------------
            {
                CHAR _iName[16], _tName[16], _extra[64];
                CopyProcessName(PsGetCurrentProcessId(), _iName);
                CopyProcessName(targetPid, _tName);
                // ExtendedParameterCount 记录扩展参数数量，供后续分析
                _snprintf_s(_extra, sizeof(_extra), _TRUNCATE,
                    "AllocType=0x%08X ExtParams=%lu",
                    AllocationType, ExtendedParameterCount);
                FileLogger_LogProtectionChange(
                    "NtAllocateVirtualMemoryEx",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _iName,
                    (ULONG)(ULONG_PTR)targetPid, _tName,
                    (ULONG_PTR)*BaseAddress, *RegionSize,
                    PageProtection, newProtect, status, _extra
                );
            }
        }

        return status;
    }

    return g_OrigNtAllocateVirtualMemoryEx(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        AllocationType,
        PageProtection,
        ExtendedParameters,
        ExtendedParameterCount
    );
}

static NTSTATUS Detour_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
)
{
    // ---- KiUED Hook 保护：阻止将 KiUED 所在页改为可写 ----
    // 含写权限的保护属性掩码
    #define WRITE_FLAGS (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    if (BaseAddress && RegionSize) {
        __try {
            ULONG_PTR addr = (ULONG_PTR)*BaseAddress;
            SIZE_T    size = *RegionSize;
            if ((NewProtect & WRITE_FLAGS) &&
                IsOverlappingKiUedPage(addr, size ? size : 1))
            {
                HANDLE protTargetPid = NULL;
                if (IsMonitoredProcess(ProcessHandle, &protTargetPid)) {
                    ULONG srcPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                    DBG_PRINT("Detour_NtProtectVirtualMemory: *** BLOCKED *** "
                        "PID %lu -> %lu 试图修改 KiUED 所在页权限为 %s [%p+0x%llX]\n",
                        srcPid, (ULONG)(ULONG_PTR)protTargetPid,
                        ProtectionToString(NewProtect),
                        (PVOID)addr, (ULONG64)size);

                    // PROTECT_BLOCK 事件日志
                    {
                        CHAR _pName[16], pArgs[200];
                        CopyProcessName(PsGetCurrentProcessId(), _pName);
                        _snprintf_s(pArgs, sizeof(pArgs), _TRUNCATE,
                            "PID=%lu Name=%s Addr=%08llX RequestedProt=%s",
                            srcPid, _pName,
                            (ULONG64)addr, ProtectionToString(NewProtect));
                        FileLogger_LogEvent("PROTECT_BLOCK", pArgs);
                    }

                    return STATUS_ACCESS_DENIED;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // BaseAddress/RegionSize 是用户态指针，读取可能异常，忽略即可
        }
    }

    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    BOOLEAN shouldIntercept = ShouldIntercept(ProcessHandle, NewProtect, &targetPid, &createTime,
        "NtProtectVirtualMemory");

    if (shouldIntercept) {
        ULONG modifiedProtect = RemoveExecuteProtection(NewProtect);

        DBG_PRINT("Detour_NtProtectVirtualMemory: PID %lu -> %lu, Protection %s -> %s\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG)(ULONG_PTR)targetPid,
            ProtectionToString(NewProtect),
            ProtectionToString(modifiedProtect));

        NTSTATUS status = g_OrigNtProtectVirtualMemory(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            modifiedProtect,
            OldProtect
        );

        if (NT_SUCCESS(status) && BaseAddress && *BaseAddress && RegionSize && *RegionSize) {
            // 检查是否已有记录

            // -------------------------------------------------------
            // [FileLogger] 记录 NtProtectVirtualMemory 权限降级事件
            // 在 syscall 成功后、DataManager 查询前记录，确保即使后续失败也能留存日志
            // OldProtect 来自用户态，使用 SEH 保护读取（防止进程异常导致内核崩溃）
            // -------------------------------------------------------
            {
                CHAR _iName[16], _tName[16], _extra[64];
                CopyProcessName(PsGetCurrentProcessId(), _iName);
                CopyProcessName(targetPid, _tName);
                // OldProtect 是用户态指针，需用 SEH 保护读取
                ULONG _prevProt = 0;
                if (OldProtect) {
                    __try   { _prevProt = *OldProtect; }
                    __except(EXCEPTION_EXECUTE_HANDLER) { _prevProt = 0; }
                }
                // OldProt 记录系统返回的"修改前"实际保护属性
                _snprintf_s(_extra, sizeof(_extra), _TRUNCATE,
                    "OldProt=%s", ProtectionToString(_prevProt));
                FileLogger_LogProtectionChange(
                    "NtProtectVirtualMemory",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _iName,
                    (ULONG)(ULONG_PTR)targetPid, _tName,
                    (ULONG_PTR)*BaseAddress, *RegionSize,
                    NewProtect, modifiedProtect, status, _extra
                );
            }
            PPROCESS_NODE processNode = NULL;
            PMEMORY_REGION_NODE regionNode = DataManager_FindMemoryRegionByPidAndAddress(
                targetPid,
                (ULONG_PTR)*BaseAddress,
                &processNode
            );

            if (regionNode && processNode) {
                // 更新已有记录
                DataManager_UpdateMemoryRegion(
                    processNode,
                    (ULONG_PTR)*BaseAddress,
                    &modifiedProtect,
                    &NewProtect,
                    NULL,
                    RegionSize
                );
                DataManager_ReleaseProcess(processNode);
            }
            else {
                // 新记录
                if (processNode) {
                    DataManager_ReleaseProcess(processNode);
                }
                RecordAndInstallHook(
                    targetPid,
                    createTime,
                    *BaseAddress,
                    *RegionSize,
                    NewProtect,
                    modifiedProtect
                );
            }
        }

        return status;
    }

    return g_OrigNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect
    );
}

static NTSTATUS Detour_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
)
{
    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    BOOLEAN shouldIntercept = ShouldIntercept(ProcessHandle, Win32Protect, &targetPid, &createTime,
        "NtMapViewOfSection");

    if (shouldIntercept) {
        ULONG newProtect = RemoveExecuteProtection(Win32Protect);

        DBG_PRINT("Detour_NtMapViewOfSection: PID %lu -> %lu, Protection %s -> %s\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG)(ULONG_PTR)targetPid,
            ProtectionToString(Win32Protect),
            ProtectionToString(newProtect));

        // 先用原始保护调用，然后修改
        NTSTATUS status = g_OrigNtMapViewOfSection(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect
        );

        if (NT_SUCCESS(status) && BaseAddress && *BaseAddress) {
            SIZE_T size = (ViewSize && *ViewSize) ? *ViewSize : PAGE_SIZE;

            // 修改保护属性
            PVOID addr = *BaseAddress;
            ULONG oldProt = 0;

            ZwProtectVirtualMemory(
                ProcessHandle,
                &addr,
                &size,
                newProtect,
                &oldProt
            );

            RecordAndInstallHook(
                targetPid,
                createTime,
                *BaseAddress,
                size,
                Win32Protect,
                newProtect
            );

            // -------------------------------------------------------
            // [FileLogger] 记录 NtMapViewOfSection 权限降级事件
            // 注意：本 Detour 先以原始权限映射，再用 ZwProtectVirtualMemory 降级，
            //       因此 SyscallStatus 为映射操作的状态，权限修改状态不单独上报
            // -------------------------------------------------------
            {
                CHAR _iName[16], _tName[16], _extra[64];
                CopyProcessName(PsGetCurrentProcessId(), _iName);
                CopyProcessName(targetPid, _tName);
                // SectionOffset 为可选参数，为 NULL 时视为从节起始位置映射
                LONGLONG _sOff = SectionOffset ? SectionOffset->QuadPart : 0LL;
                _snprintf_s(_extra, sizeof(_extra), _TRUNCATE,
                    "SectionOff=0x%016llX", (ULONG64)_sOff);
                FileLogger_LogProtectionChange(
                    "NtMapViewOfSection",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _iName,
                    (ULONG)(ULONG_PTR)targetPid, _tName,
                    (ULONG_PTR)*BaseAddress, size,
                    Win32Protect, newProtect, status, _extra
                );
            }
        }

        return status;
    }

    return g_OrigNtMapViewOfSection(
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        CommitSize,
        SectionOffset,
        ViewSize,
        InheritDisposition,
        AllocationType,
        Win32Protect
    );
}

static NTSTATUS Detour_NtMapViewOfSectionEx(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
)
{
    HANDLE targetPid = NULL;
    LONGLONG createTime = 0;

    BOOLEAN shouldIntercept = ShouldIntercept(ProcessHandle, PageProtection, &targetPid, &createTime,
        "NtMapViewOfSectionEx");

    if (shouldIntercept) {
        ULONG newProtect = RemoveExecuteProtection(PageProtection);

        DBG_PRINT("Detour_NtMapViewOfSectionEx: PID %lu -> %lu, Protection %s -> %s\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG)(ULONG_PTR)targetPid,
            ProtectionToString(PageProtection),
            ProtectionToString(newProtect));

        NTSTATUS status = g_OrigNtMapViewOfSectionEx(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            SectionOffset,
            ViewSize,
            AllocationType,
            PageProtection,
            ExtendedParameters,
            ExtendedParameterCount
        );

        if (NT_SUCCESS(status) && BaseAddress && *BaseAddress) {
            SIZE_T size = (ViewSize && *ViewSize) ? *ViewSize : PAGE_SIZE;

            PVOID addr = *BaseAddress;
            ULONG oldProt = 0;

            ZwProtectVirtualMemory(
                ProcessHandle,
                &addr,
                &size,
                newProtect,
                &oldProt
            );

            RecordAndInstallHook(
                targetPid,
                createTime,
                *BaseAddress,
                size,
                PageProtection,
                newProtect
            );

            // -------------------------------------------------------
            // [FileLogger] 记录 NtMapViewOfSectionEx 权限降级事件
            // -------------------------------------------------------
            {
                CHAR _iName[16], _tName[16], _extra[64];
                CopyProcessName(PsGetCurrentProcessId(), _iName);
                CopyProcessName(targetPid, _tName);
                LONGLONG _sOff = SectionOffset ? SectionOffset->QuadPart : 0LL;
                _snprintf_s(_extra, sizeof(_extra), _TRUNCATE,
                    "SectionOff=0x%016llX ExtParams=%lu",
                    (ULONG64)_sOff, ExtendedParameterCount);
                FileLogger_LogProtectionChange(
                    "NtMapViewOfSectionEx",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _iName,
                    (ULONG)(ULONG_PTR)targetPid, _tName,
                    (ULONG_PTR)*BaseAddress, size,
                    PageProtection, newProtect, status, _extra
                );
            }
        }

        return status;
    }

    return g_OrigNtMapViewOfSectionEx(
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        SectionOffset,
        ViewSize,
        AllocationType,
        PageProtection,
        ExtendedParameters,
        ExtendedParameterCount
    );
}

static NTSTATUS Detour_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
)
{
    // 先调用原始函数
    NTSTATUS status = g_OrigNtWriteVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        BufferSize,
        NumberOfBytesWritten
    );

    // 如果写入成功且是远程进程
    if (NT_SUCCESS(status) && IsRemoteProcess(ProcessHandle)) {
        HANDLE targetPid = NULL;
        LONGLONG createTime = 0;

        if (NT_SUCCESS(Utils_GetPidFromHandle(ProcessHandle, &targetPid, &createTime))) {
            // 查找对应的内存区域
            PPROCESS_NODE processNode = NULL;
            PMEMORY_REGION_NODE regionNode = DataManager_FindMemoryRegionByPidAndAddress(
                targetPid,
                (ULONG_PTR)BaseAddress,
                &processNode
            );

            if (regionNode && processNode) {
                // 标记为脏
                BOOLEAN dirty = TRUE;
                DataManager_UpdateMemoryRegion(
                    processNode,
                    (ULONG_PTR)BaseAddress,
                    NULL,
                    NULL,
                    &dirty,
                    &BufferSize
                );

                DBG_PRINT("Detour_NtWriteVirtualMemory: Marked region [%p] as dirty, "
                    "HookInstalled=%d DllConnected=%d\n",
                    BaseAddress,
                    (int)processNode->IsHookInstalled,
                    (int)processNode->DllConnected);

                // WRITE_MARK 事件日志
                {
                    CHAR _wSrc[16], _wDst[16], wArgs[200];
                    CopyProcessName(PsGetCurrentProcessId(), _wSrc);
                    CopyProcessName(targetPid, _wDst);
                    _snprintf_s(wArgs, sizeof(wArgs), _TRUNCATE,
                        "SrcPID=%lu SrcName=%s DstPID=%lu DstName=%s Addr=%08llX Size=%llX",
                        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _wSrc,
                        (ULONG)(ULONG_PTR)targetPid, _wDst,
                        (ULONG64)(ULONG_PTR)BaseAddress, (ULONG64)BufferSize);
                    FileLogger_LogEvent("WRITE_MARK", wArgs);
                }
            }

            if (processNode) {
                DataManager_ReleaseProcess(processNode);
            }
        }
    }

    return status;
}

// ============================================================================
// Detour_NtQueryVirtualMemory — 欺骗跨进程权限查询
// 当注入器查询受控内存区域的保护属性时，补回被移除的执行位，
// 使注入器看到原始权限（如 RWX 而非 RW-），避免其发现权限被篡改
// ============================================================================

static NTSTATUS Detour_NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
)
{
    // 先调用原始函数
    NTSTATUS status = g_OrigNtQueryVirtualMemory(
        ProcessHandle,
        BaseAddress,
        MemoryInformationClass,
        MemoryInformation,
        MemoryInformationLength,
        ReturnLength
    );

    // 仅对成功的跨进程 MemoryBasicInformation 查询进行欺骗
    if (!NT_SUCCESS(status) ||
        !IsRemoteProcess(ProcessHandle) ||
        MemoryInformationClass != (MEMORY_INFORMATION_CLASS)0 || // MemoryBasicInformation
        !MemoryInformation ||
        MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
    {
        return status;
    }

    // 获取目标进程 PID
    HANDLE targetPid = NULL;
    if (!NT_SUCCESS(Utils_GetPidFromHandle(ProcessHandle, &targetPid, NULL))) {
        return status;
    }

    // 查找受控内存区域快照，避免在 AVL 锁外解引用节点裸指针
    MEMORY_REGION_NODE regionSnapshot = { 0 };
    if (DataManager_QueryMemoryRegionSnapshot(
        targetPid,
        (ULONG_PTR)BaseAddress,
        &regionSnapshot))
    {
        // 受控区域命中：将返回的 Protect 补回原始执行位
        __try {
            PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;
            ULONG origProt = regionSnapshot.OriginalProtection;

            if (HasExecuteProtection(origProt) && !HasExecuteProtection(mbi->Protect)) {
                ULONG realProt = mbi->Protect;
                DBG_PRINT("Detour_NtQueryVirtualMemory: PID %lu 查询 PID %lu 地址 %p, "
                    "伪装 Protect %s -> %s\n",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                    (ULONG)(ULONG_PTR)targetPid,
                    BaseAddress,
                    ProtectionToString(realProt),
                    ProtectionToString(origProt));
                mbi->Protect = origProt;

                // SPOOF 事件日志
                {
                    CHAR _qSrc[16], _qDst[16], qArgs[256];
                    CopyProcessName(PsGetCurrentProcessId(), _qSrc);
                    CopyProcessName(targetPid, _qDst);
                    _snprintf_s(qArgs, sizeof(qArgs), _TRUNCATE,
                        "QueryPID=%lu QueryName=%s TargetPID=%lu TargetName=%s "
                        "Addr=%08llX FakeProt=%s RealProt=%s",
                        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), _qSrc,
                        (ULONG)(ULONG_PTR)targetPid, _qDst,
                        (ULONG64)(ULONG_PTR)BaseAddress,
                        ProtectionToString(origProt),
                        ProtectionToString(realProt));
                    FileLogger_LogEvent("SPOOF", qArgs);
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // MemoryInformation 是用户态指针，写入可能异常
        }
    }

    return status;
}

// ============================================================================
// 公共API实现
// ============================================================================

// 注意：实际的Hook安装依赖于ETW Hook机制
// 这里提供的是接口封装，需要与etwhook_manager配合使用

NTSTATUS SyscallHook_Initialize(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    if (g_SyscallHookInitialized) {
        return STATUS_SUCCESS;
    }

    DBG_PRINT("SyscallHook_Initialize: Starting initialization\n");

    // 初始化SSDT
    NTSTATUS status = Utils_InitializeSSDT(DriverObject);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("SyscallHook_Initialize: Failed to initialize SSDT (0x%08X)\n", status);
        // 继续执行，可能可以通过其他方式获取函数地址
    }

    // 获取原始函数地址
    // 这些函数地址将用于调用原始系统调用

    // NtAllocateVirtualMemory
    g_OrigNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtAllocateVirtualMemory"));

    // NtAllocateVirtualMemoryEx
    g_OrigNtAllocateVirtualMemoryEx = (PFN_NtAllocateVirtualMemoryEx)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtAllocateVirtualMemoryEx"));

    // NtProtectVirtualMemory
    g_OrigNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtProtectVirtualMemory"));

    // NtMapViewOfSection
    g_OrigNtMapViewOfSection = (PFN_NtMapViewOfSection)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtMapViewOfSection"));

    // NtMapViewOfSectionEx
    g_OrigNtMapViewOfSectionEx = (PFN_NtMapViewOfSectionEx)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtMapViewOfSectionEx"));

    // NtWriteVirtualMemory
    g_OrigNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtWriteVirtualMemory"));

    // NtQueryVirtualMemory
    g_OrigNtQueryVirtualMemory = (PFN_NtQueryVirtualMemory)
        Utils_GetSSDTFunctionAddress(Utils_GetSSDTIndex("NtQueryVirtualMemory"));

    DBG_PRINT("SyscallHook_Initialize: Original function addresses:\n");
    DBG_PRINT("  NtAllocateVirtualMemory = %p\n", g_OrigNtAllocateVirtualMemory);
    DBG_PRINT("  NtAllocateVirtualMemoryEx = %p\n", g_OrigNtAllocateVirtualMemoryEx);
    DBG_PRINT("  NtProtectVirtualMemory = %p\n", g_OrigNtProtectVirtualMemory);
    DBG_PRINT("  NtMapViewOfSection = %p\n", g_OrigNtMapViewOfSection);
    DBG_PRINT("  NtMapViewOfSectionEx = %p\n", g_OrigNtMapViewOfSectionEx);
    DBG_PRINT("  NtWriteVirtualMemory = %p\n", g_OrigNtWriteVirtualMemory);
    DBG_PRINT("  NtQueryVirtualMemory = %p\n", g_OrigNtQueryVirtualMemory);

    // 如果关键函数获取失败，使用Zw版本
    if (!g_OrigNtAllocateVirtualMemory) {
        g_OrigNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)ZwAllocateVirtualMemory;
    }
    if (!g_OrigNtProtectVirtualMemory) {
        g_OrigNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)ZwProtectVirtualMemory;
    }

    g_SyscallHookInitialized = TRUE;

    DBG_PRINT("SyscallHook_Initialize: Initialization complete\n");
    return STATUS_SUCCESS;
}

VOID SyscallHook_Cleanup(VOID)
{
    DBG_PRINT("SyscallHook_Cleanup: Starting cleanup\n");

    // 禁用所有Hook
    SyscallHook_DisableAll();

    g_SyscallHookInitialized = FALSE;

    DBG_PRINT("SyscallHook_Cleanup: Cleanup complete\n");
}

NTSTATUS SyscallHook_EnableAll(VOID)
{
    if (!g_SyscallHookInitialized) {
        return STATUS_UNSUCCESSFUL;
    }
    auto status = EtwHookManager::get_instance()->init();
    for (int i = 0; i < HookedSyscall_Max; i++) {
        SyscallHook_Enable((HOOKED_SYSCALL)i);
    }

    return status;
}

NTSTATUS SyscallHook_DisableAll(VOID)
{   
    auto status = EtwHookManager::get_instance()->destory();
    for (int i = 0; i < HookedSyscall_Max; i++) {
        SyscallHook_Disable((HOOKED_SYSCALL)i);
    }

    return status;
}

NTSTATUS SyscallHook_Enable(_In_ HOOKED_SYSCALL SyscallId)
{
    if (SyscallId >= HookedSyscall_Max) return STATUS_INVALID_PARAMETER;

    // 1. 获取对应的函数指针
    PVOID* ppOriginalFunc = (PVOID*)SyscallHook_GetOriginalFunction(SyscallId);
    PVOID detourFunc = SyscallHook_GetDetourFunction(SyscallId);

    if (!detourFunc) return STATUS_UNSUCCESSFUL;

    g_HooksEnabled[SyscallId] = TRUE;

    // 2. 注册原始函数地址与 detour 的映射
    EtwHookManager::get_instance()->add_hook(
        ppOriginalFunc,
        detourFunc
    );

    DBG_PRINT("SyscallHook_Enable: Enabled hook %d\n", SyscallId);
    return STATUS_SUCCESS;
}

NTSTATUS SyscallHook_Disable(
    _In_ HOOKED_SYSCALL SyscallId
)
{
    if (SyscallId >= HookedSyscall_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID* ppOriginalFunc = (PVOID*)SyscallHook_GetOriginalFunction(SyscallId);

    g_HooksEnabled[SyscallId] = FALSE;

    EtwHookManager::get_instance()->remove_hook(ppOriginalFunc);

    DBG_PRINT("SyscallHook_Disable: Disabled hook %d\n", SyscallId);

    return STATUS_SUCCESS;
}

NTSTATUS SyscallHook_RegisterPreCallback(
    _In_ SYSCALL_PRE_CALLBACK Callback
)
{
    g_PreCallback = Callback;
    return STATUS_SUCCESS;
}

NTSTATUS SyscallHook_RegisterPostCallback(
    _In_ SYSCALL_POST_CALLBACK Callback
)
{
    g_PostCallback = Callback;
    return STATUS_SUCCESS;
}

BOOLEAN SyscallHook_IsInitialized(VOID)
{
    return g_SyscallHookInitialized;
}

BOOLEAN SyscallHook_IsEnabled(
    _In_ HOOKED_SYSCALL SyscallId
)
{
    if (SyscallId >= HookedSyscall_Max) {
        return FALSE;
    }
    return g_HooksEnabled[SyscallId];
}

PVOID SyscallHook_GetOriginalFunction(
    _In_ HOOKED_SYSCALL SyscallId
)
{
    switch (SyscallId) {
    case HookedSyscall_NtAllocateVirtualMemory:
        return (PVOID)g_OrigNtAllocateVirtualMemory;
    case HookedSyscall_NtAllocateVirtualMemoryEx:
        return (PVOID)g_OrigNtAllocateVirtualMemoryEx;
    case HookedSyscall_NtProtectVirtualMemory:
        return (PVOID)g_OrigNtProtectVirtualMemory;
    case HookedSyscall_NtMapViewOfSection:
        return (PVOID)g_OrigNtMapViewOfSection;
    case HookedSyscall_NtMapViewOfSectionEx:
        return (PVOID)g_OrigNtMapViewOfSectionEx;
    case HookedSyscall_NtWriteVirtualMemory:
        return (PVOID)g_OrigNtWriteVirtualMemory;
    case HookedSyscall_NtQueryVirtualMemory:
        return (PVOID)g_OrigNtQueryVirtualMemory;
    default:
        return NULL;
    }
}

// ============================================================================
// 导出Detour函数供ETW Hook使用
// ============================================================================

PVOID SyscallHook_GetDetourFunction(
    _In_ HOOKED_SYSCALL SyscallId
)
{
    switch (SyscallId) {
    case HookedSyscall_NtAllocateVirtualMemory:
        return (PVOID)Detour_NtAllocateVirtualMemory;
    case HookedSyscall_NtAllocateVirtualMemoryEx:
        return (PVOID)Detour_NtAllocateVirtualMemoryEx;
    case HookedSyscall_NtProtectVirtualMemory:
        return (PVOID)Detour_NtProtectVirtualMemory;
    case HookedSyscall_NtMapViewOfSection:
        return (PVOID)Detour_NtMapViewOfSection;
    case HookedSyscall_NtMapViewOfSectionEx:
        return (PVOID)Detour_NtMapViewOfSectionEx;
    case HookedSyscall_NtWriteVirtualMemory:
        return (PVOID)Detour_NtWriteVirtualMemory;
    case HookedSyscall_NtQueryVirtualMemory:
        return (PVOID)Detour_NtQueryVirtualMemory;
    default:
        return NULL;
    }
}

// ============================================================================
// KiUED Hook 保护：设置全局地址
// ============================================================================

VOID SyscallHook_SetKiUedAddress(_In_ PVOID Address)
{
    if (!g_KiUedAddress && Address) {
        InterlockedExchangePointer((PVOID*)&g_KiUedAddress, Address);
        DBG_PRINT("SyscallHook_SetKiUedAddress: KiUED=0x%p — Hook 保护已启用\n", Address);
    }
}
