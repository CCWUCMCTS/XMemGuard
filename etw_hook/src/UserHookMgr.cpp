// ============================================================================
// UserHookMgr.cpp - 用户态Hook管理器实现

#include "UserHookMgr.hpp"
#include <ntstrsafe.h>
#include <ntimage.h>
#include <stdio.h>

// WORD/PWORD 在纯内核模式头文件链中可能未定义（内核推荐用 USHORT/PUSHORT，但 ntimage.h 里用到了 WORD）
#ifndef WORD
typedef unsigned short WORD;
#endif
#ifndef PWORD
typedef WORD* PWORD;
#endif

#include "Utils.hpp"
#include "DataManager.hpp"
#include "FileLogger.hpp"

// ============================================================================
// UserHookMgr_Initialize / Cleanup

static BOOLEAN g_UserHookMgrInitialized = FALSE;

// DLL 路径常量（Kernel Manual Map 注入使用，定义在 Common.hpp）
static const WCHAR g_DllPath_x64[] = INJECT_DLL_PATH_X64;
static const WCHAR g_DllPath_x86[] = INJECT_DLL_PATH_X86;

// ZwCreateThreadEx：在目标进程创建新线程同步执行 DllMain，
// 彻底绕开 APC 投递依赖可警觉等待的可靠性问题
typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    _Out_ PHANDLE              ThreadHandle,
    _In_  ACCESS_MASK          DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  HANDLE               ProcessHandle,
    _In_  PVOID                StartRoutine,
    _In_opt_ PVOID             Argument,
    _In_  ULONG                CreateFlags,
    _In_  ULONG_PTR            ZeroBits,
    _In_  SIZE_T               StackSize,
    _In_  SIZE_T               MaximumStackSize,
    _In_opt_ PVOID             AttributeList
);
static PFN_ZwCreateThreadEx g_ZwCreateThreadEx = NULL;

// 系统调用号缓存 (全局，因为同一系统调用号固定不变)
static USHORT g_SyscallNumber_NtDeviceIoControlFile = 0;
static USHORT g_SyscallNumber_NtContinue = 0;
static USHORT g_SyscallNumber_NtProtectVirtualMemory = 0;
static USHORT g_SyscallNumber_NtAllocateVirtualMemory = 0;
static USHORT g_SyscallNumber_NtWriteVirtualMemory = 0;

// ============================================================================
// 前置声明
// ============================================================================


// ============================================================================

NTSTATUS UserHookMgr_Initialize(VOID)
{
    if (g_UserHookMgrInitialized) {
        return STATUS_SUCCESS;
    }

    // 解析 ZwCreateThreadEx：在目标进程创建线程同步执行 DllMain
    UNICODE_STRING fnName;
    RtlInitUnicodeString(&fnName, L"ZwCreateThreadEx");
    g_ZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fnName);
    if (g_ZwCreateThreadEx) {
        DBG_PRINT("UserHookMgr_Initialize: ZwCreateThreadEx 解析成功\n");
    } else {
        DBG_PRINT("UserHookMgr_Initialize: ZwCreateThreadEx 未找到，将在首次注入时通过 SSDT 解析\n");
    }

    // Cache syscall numbers for use by injected shellcode
    g_SyscallNumber_NtDeviceIoControlFile   = Utils_GetSyscallNumber("NtDeviceIoControlFile");
    g_SyscallNumber_NtContinue              = Utils_GetSyscallNumber("NtContinue");
    g_SyscallNumber_NtProtectVirtualMemory  = Utils_GetSyscallNumber("NtProtectVirtualMemory");
    g_SyscallNumber_NtAllocateVirtualMemory = Utils_GetSyscallNumber("NtAllocateVirtualMemory");
    g_SyscallNumber_NtWriteVirtualMemory    = Utils_GetSyscallNumber("NtWriteVirtualMemory");

    DBG_PRINT("UserHookMgr_Initialize: NtDeviceIoControlFile=%u NtContinue=%u NtProtect=%u\n",
        g_SyscallNumber_NtDeviceIoControlFile,
        g_SyscallNumber_NtContinue,
        g_SyscallNumber_NtProtectVirtualMemory);

    g_UserHookMgrInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID UserHookMgr_Cleanup(VOID)
{
    g_UserHookMgrInitialized = FALSE;
    DBG_PRINT("UserHookMgr_Cleanup: done\n");
}

// ============================================================================
// UserHookMgr_GetKiUserExceptionDispatcher
// ============================================================================

PVOID UserHookMgr_GetKiUserExceptionDispatcher(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN   IsWow64
)
{
    UNICODE_STRING ntdllName;
    RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

    // Must be called while already attached to the target process
    PVOID ntdllBase = Utils_GetUserModuleBase(Process, &ntdllName, IsWow64);
    if (!ntdllBase) {
        DBG_PRINT("UserHookMgr_GetKiUserExceptionDispatcher: ntdll.dll not found\n");
        return NULL;
    }

    PVOID addr = Utils_GetModuleExportAddress(Process, ntdllBase, "KiUserExceptionDispatcher");
    DBG_PRINT("UserHookMgr_GetKiUserExceptionDispatcher: ntdll=%p KiUED=%p IsWow64=%d\n",
        ntdllBase, addr, (int)IsWow64);
    return addr;
}

// ============================================================================
// UserHookMgr_AllocateMemoryInProcess
// ============================================================================

NTSTATUS UserHookMgr_AllocateMemoryInProcess(
    _In_  PEPROCESS  Process,
    _Out_ PVOID*     BaseAddress,
    _In_  SIZE_T     Size,
    _In_  ULONG      Protection
)
{
    KAPC_STATE apcState;
    *BaseAddress = NULL;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);
    SIZE_T allocSize = Size;
    NTSTATUS status = ZwAllocateVirtualMemory(
        NtCurrentProcess(), BaseAddress, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, Protection);
    KeUnstackDetachProcess(&apcState);

    return status;
}

// ============================================================================
// PreviousMode 辅助函数
// 通过 SSDT 直接调用 Nt* 函数时，必须将当前线程 PreviousMode 设为 KernelMode，
// 否则 Nt 函数会以 UserMode 语义执行：
//   - ObReferenceObjectByHandle 查用户句柄表（OBJ_KERNEL_HANDLE 不可见）→ INVALID_HANDLE
//   - ProbeForWrite 检查 OUT 参数是否在用户地址空间（内核栈指针不合法）→ ACCESS_VIOLATION
// KTHREAD.PreviousMode 偏移 = 0x232，适用于 Windows 10 RS3 (1709) ~ Windows 11 24H2 (26100)
// ============================================================================
#define KTHREAD_PREVIOUSMODE_OFFSET 0x232

static KPROCESSOR_MODE SetCurrentThreadPreviousModeKernel(VOID)
{
    PUCHAR kthread = (PUCHAR)KeGetCurrentThread();
    KPROCESSOR_MODE old = *(KPROCESSOR_MODE*)(kthread + KTHREAD_PREVIOUSMODE_OFFSET);
    *(KPROCESSOR_MODE*)(kthread + KTHREAD_PREVIOUSMODE_OFFSET) = KernelMode;
    return old;
}

static VOID RestoreCurrentThreadPreviousMode(KPROCESSOR_MODE OldMode)
{
    PUCHAR kthread = (PUCHAR)KeGetCurrentThread();
    *(KPROCESSOR_MODE*)(kthread + KTHREAD_PREVIOUSMODE_OFFSET) = OldMode;
}

// ============================================================================
// UserHookMgr_WriteProcessMemory
// ============================================================================

NTSTATUS UserHookMgr_WriteProcessMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID     TargetAddress,
    _In_ PVOID     SourceBuffer,
    _In_ SIZE_T    Size
)
{
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);
    __try {
        RtlCopyMemory(TargetAddress, SourceBuffer, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    KeUnstackDetachProcess(&apcState);
    return status;
}

// ============================================================================
// UserHookMgr_ReadProcessMemory
// ============================================================================

NTSTATUS UserHookMgr_ReadProcessMemory(
    _In_  PEPROCESS Process,
    _In_  PVOID     SourceAddress,
    _Out_ PVOID     TargetBuffer,
    _In_  SIZE_T    Size
)
{
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);
    __try {
        RtlCopyMemory(TargetBuffer, SourceAddress, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    KeUnstackDetachProcess(&apcState);
    return status;
}


// ============================================================================
// 全局变量
// ============================================================================




// ============================================================================

static NTSTATUS UserHookMgr_PrepareHookInfo(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN IsWow64,
    _Out_ PPROCESS_HOOK_INFO HookInfo
);

// ============================================================================
// UserHookMgr_InjectShellcode (Kernel Manual Map 版)
// 在内核态手动映射 InjectDll.dll 到目标进程，通过 ZwCreateThreadEx 同步执行 DllMain。
// 不依赖 LoadLibraryW 和 loader 锁，不依赖 APC 投递，适用于 PoolParty 等攻击场景。
// ============================================================================
static NTSTATUS UserHookMgr_PrepareHookInfo(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN IsWow64,
    _Out_ PPROCESS_HOOK_INFO HookInfo
)
{
    RtlZeroMemory(HookInfo, sizeof(PROCESS_HOOK_INFO));

    HookInfo->Process   = Process;
    HookInfo->ProcessId = PsGetProcessId(Process);
    HookInfo->IsWow64   = IsWow64;
    HookInfo->State     = HookStateNone;

    // 获取 KiUserExceptionDispatcher 地址（附加到目标进程读取）
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    HookInfo->OriginalFuncAddr = UserHookMgr_GetKiUserExceptionDispatcher(Process, IsWow64);

    // 同时读取原始 14 字节（供 Trampoline 和恢复使用）
    if (HookInfo->OriginalFuncAddr) {
        NTSTATUS rdStatus = Utils_SafeReadUserMemory(
            HookInfo->OriginalFuncAddr,
            HookInfo->OriginalBytes,
            14  // 绝对间接跳转大小
        );
        if (NT_SUCCESS(rdStatus)) {
            HookInfo->OriginalBytesSize = 14;
        }
    }

    KeUnstackDetachProcess(&apcState);

    if (!HookInfo->OriginalFuncAddr) {
        DBG_PRINT("UserHookMgr_PrepareHookInfo: KiUserExceptionDispatcher not found\n");
        return STATUS_NOT_FOUND;
    }

    // 缓存系统调用号
    HookInfo->SyscallNtDeviceIoControlFile    = g_SyscallNumber_NtDeviceIoControlFile;
    HookInfo->SyscallNtContinue              = g_SyscallNumber_NtContinue;
    HookInfo->SyscallNtProtectVirtualMemory  = g_SyscallNumber_NtProtectVirtualMemory;

    DBG_PRINT("UserHookMgr_PrepareHookInfo: PID=%lu KiUED=%p OrigBytesSize=%zu\n",
        (ULONG)(ULONG_PTR)HookInfo->ProcessId,
        HookInfo->OriginalFuncAddr,
        HookInfo->OriginalBytesSize);

    return STATUS_SUCCESS;
}


static NTSTATUS UserHookMgr_InjectShellcode(
    _In_ PEPROCESS Process,
    _Inout_ PPROCESS_HOOK_INFO HookInfo
)
{
    NTSTATUS  status;
    KAPC_STATE apcState;
    PVOID      fileBuffer  = NULL;
    PVOID      mappedBase  = NULL;
    ULONG      sizeOfImage = 0;

    // ---- 1. 确定 DLL 路径（根据目标位数）----
    const WCHAR* dllPath = HookInfo->IsWow64 ? g_DllPath_x86 : g_DllPath_x64;

    // ---- 2. 打开 DLL 文件，读入内核缓冲区 ----
    WCHAR ntPathBuf[300];
    status = RtlStringCchPrintfW(ntPathBuf, 300, L"\\??\\%s", dllPath);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("UserHookMgr_InjectShellcode: path format failed\n");
        return status;
    }

    UNICODE_STRING dllPathUni;
    RtlInitUnicodeString(&dllPathUni, ntPathBuf);

    OBJECT_ATTRIBUTES fileAttr;
    InitializeObjectAttributes(&fileAttr, &dllPathUni,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = { 0 };
    status = ZwCreateFile(&hFile,
        FILE_GENERIC_READ | SYNCHRONIZE, &fileAttr, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("UserHookMgr_InjectShellcode: ZwCreateFile failed (0x%08X) %S\n",
            status, dllPath);
        return status;
    }

    FILE_STANDARD_INFORMATION fileStdInfo = { 0 };
    status = ZwQueryInformationFile(hFile, &iosb,
        &fileStdInfo, sizeof(fileStdInfo), FileStandardInformation);
    if (!NT_SUCCESS(status) || fileStdInfo.EndOfFile.QuadPart == 0) {
        DBG_PRINT("UserHookMgr_InjectShellcode: ZwQueryInformationFile failed (0x%08X)\n",
            status);
        ZwClose(hFile);
        return NT_SUCCESS(status) ? STATUS_INVALID_IMAGE_FORMAT : status;
    }

    ULONG fileSize = (ULONG)fileStdInfo.EndOfFile.LowPart;
    DBG_PRINT("UserHookMgr_InjectShellcode: DLL file=%S size=%lu\n", dllPath, fileSize);

    fileBuffer = ExAllocatePoolWithTag(NonPagedPool, fileSize, 'lliD');
    if (!fileBuffer) {
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(fileBuffer, fileSize);

    LARGE_INTEGER readOffset = { 0 };
    status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb,
        fileBuffer, fileSize, &readOffset, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("UserHookMgr_InjectShellcode: ZwReadFile failed (0x%08X)\n", status);
        goto Cleanup;
    }

    // ---- 3. 验证 PE 头（支持 PE32 和 PE32+）----
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            DBG_PRINT("UserHookMgr_InjectShellcode: bad DOS signature\n");
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }

        // 通过 FileHeader.Machine 判断 PE 位数
        PIMAGE_FILE_HEADER peFileHdr = (PIMAGE_FILE_HEADER)((PUCHAR)fileBuffer + dos->e_lfanew + sizeof(ULONG));
        BOOLEAN isPE32 = (peFileHdr->Machine == IMAGE_FILE_MACHINE_I386);

        // 通用变量：从 PE32 或 PE32+ 中提取
        ULONG_PTR preferredBase;
        ULONG     sizeOfHeaders;
        ULONG     addressOfEntryPoint;
        IMAGE_DATA_DIRECTORY relocDir  = { 0 };
        IMAGE_DATA_DIRECTORY importDir = { 0 };
        IMAGE_DATA_DIRECTORY excDir    = { 0 };

        if (isPE32) {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)((PUCHAR)fileBuffer + dos->e_lfanew);
            if (nt32->Signature != IMAGE_NT_SIGNATURE) {
                DBG_PRINT("UserHookMgr_InjectShellcode: bad NT signature (PE32)\n");
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto Cleanup;
            }
            sizeOfImage         = nt32->OptionalHeader.SizeOfImage;
            preferredBase       = nt32->OptionalHeader.ImageBase;
            sizeOfHeaders       = nt32->OptionalHeader.SizeOfHeaders;
            addressOfEntryPoint = nt32->OptionalHeader.AddressOfEntryPoint;
            relocDir  = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            importDir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            // x86 不使用 PDATA 异常目录
        } else {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)((PUCHAR)fileBuffer + dos->e_lfanew);
            if (nt64->Signature != IMAGE_NT_SIGNATURE) {
                DBG_PRINT("UserHookMgr_InjectShellcode: bad NT signature (PE32+)\n");
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto Cleanup;
            }
            sizeOfImage         = nt64->OptionalHeader.SizeOfImage;
            preferredBase       = (ULONG_PTR)nt64->OptionalHeader.ImageBase;
            sizeOfHeaders       = nt64->OptionalHeader.SizeOfHeaders;
            addressOfEntryPoint = nt64->OptionalHeader.AddressOfEntryPoint;
            relocDir  = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            importDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            excDir    = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        }

        DBG_PRINT("UserHookMgr_InjectShellcode: %s SizeOfImage=0x%lX PreferredBase=0x%llX\n",
            isPE32 ? "PE32" : "PE32+", sizeOfImage, (ULONG64)preferredBase);

        // ---- 4. 在目标进程分配 SizeOfImage 字节（优先首选基地址）----
        mappedBase = (PVOID)preferredBase;
        SIZE_T allocSize = sizeOfImage;

        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        status = ZwAllocateVirtualMemory(NtCurrentProcess(), &mappedBase, 0, &allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            mappedBase = NULL;
            allocSize  = sizeOfImage;
            status = ZwAllocateVirtualMemory(NtCurrentProcess(), &mappedBase, 0, &allocSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        KeUnstackDetachProcess(&apcState);

        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: ZwAllocateVirtualMemory failed (0x%08X)\n",
                status);
            mappedBase = NULL;
            goto Cleanup;
        }
        DBG_PRINT("UserHookMgr_InjectShellcode: mapped base=%p\n", mappedBase);

        // ---- 5. 映射 PE 头和各 Section ----
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        __try {
            RtlCopyMemory(mappedBase, fileBuffer, sizeOfHeaders);

            // 使用 FileHeader 直接计算 Section 头位置（兼容 PE32/PE32+）
            PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
                (PUCHAR)fileBuffer + dos->e_lfanew + sizeof(ULONG)
                + sizeof(IMAGE_FILE_HEADER) + peFileHdr->SizeOfOptionalHeader);
            for (WORD i = 0; i < peFileHdr->NumberOfSections; i++) {
                if (sections[i].SizeOfRawData > 0 && sections[i].PointerToRawData > 0) {
                    PVOID  dest     = (PUCHAR)mappedBase + sections[i].VirtualAddress;
                    PVOID  src      = (PUCHAR)fileBuffer + sections[i].PointerToRawData;
                    ULONG  copySize = min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);
                    RtlCopyMemory(dest, src, copySize);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DBG_PRINT("UserHookMgr_InjectShellcode: exception mapping sections (0x%08X)\n",
                status);
        }
        KeUnstackDetachProcess(&apcState);
        if (!NT_SUCCESS(status)) goto Cleanup;

        // ---- 6. 应用基址重定位（PE32: HIGHLOW, PE32+: DIR64）----
        LONGLONG delta = (LONGLONG)((ULONG_PTR)mappedBase - preferredBase);
        if (delta != 0) {
            if (relocDir.VirtualAddress != 0 && relocDir.Size > 0) {
                KeStackAttachProcess((PRKPROCESS)Process, &apcState);
                __try {
                    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(
                        (PUCHAR)mappedBase + relocDir.VirtualAddress);
                    while (reloc->VirtualAddress != 0 &&
                           reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                        PUCHAR page       = (PUCHAR)mappedBase + reloc->VirtualAddress;
                        PWORD  entries    = (PWORD)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));
                        ULONG  numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                                            / sizeof(WORD);
                        for (ULONG j = 0; j < numEntries; j++) {
                            USHORT type = entries[j] >> 12;
                            USHORT offset = entries[j] & 0x0FFF;
                            if (isPE32) {
                                if (type == IMAGE_REL_BASED_HIGHLOW)
                                    *(LONG*)(page + offset) += (LONG)delta;
                            } else {
                                if (type == IMAGE_REL_BASED_DIR64)
                                    *(LONGLONG*)(page + offset) += delta;
                            }
                        }
                        reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DBG_PRINT("UserHookMgr_InjectShellcode: exception in reloc (0x%08X)\n",
                        status);
                }
                KeUnstackDetachProcess(&apcState);
                if (!NT_SUCCESS(status)) goto Cleanup;
            }
            DBG_PRINT("UserHookMgr_InjectShellcode: relocations applied, delta=0x%llX\n",
                (ULONG64)delta);
        }

        // ---- 7. 修复导入表（PE32: THUNK_DATA32, PE32+: THUNK_DATA64）----
        {
            if (importDir.VirtualAddress != 0 && importDir.Size > 0) {
                KeStackAttachProcess((PRKPROCESS)Process, &apcState);
                __try {
                    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
                        (PUCHAR)mappedBase + importDir.VirtualAddress);
                    for (; importDesc->Name != 0; importDesc++) {
                        PCSTR importDllName = (PCSTR)((PUCHAR)mappedBase + importDesc->Name);

                        WCHAR wImportDll[64] = { 0 };
                        SIZE_T nameLen = strlen(importDllName);
                        if (nameLen >= 64) nameLen = 63;
                        for (SIZE_T k = 0; k < nameLen; k++)
                            wImportDll[k] = (WCHAR)(UCHAR)importDllName[k];

                        UNICODE_STRING importDllUni;
                        RtlInitUnicodeString(&importDllUni, wImportDll);
                        PVOID importBase = Utils_GetUserModuleBase(Process, &importDllUni, isPE32);
                        if (!importBase) {
                            DBG_PRINT("UserHookMgr_InjectShellcode: [WARN] import DLL not found: %s\n",
                                importDllName);
                            continue;
                        }
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
                        DBG_PRINT("UserHookMgr_InjectShellcode: resolving %s (base=%p)\n",
                            importDllName, importBase);
#endif

                        ULONG resolvedCount = 0, failedCount = 0;

                        if (isPE32) {
                            // PE32: 32-bit thunk data
                            PIMAGE_THUNK_DATA32 iat32 = (PIMAGE_THUNK_DATA32)(
                                (PUCHAR)mappedBase + importDesc->FirstThunk);
                            PIMAGE_THUNK_DATA32 hint32 = importDesc->OriginalFirstThunk
                                ? (PIMAGE_THUNK_DATA32)((PUCHAR)mappedBase
                                                         + importDesc->OriginalFirstThunk)
                                : iat32;
                            for (; hint32->u1.AddressOfData != 0; iat32++, hint32++) {
                                if (hint32->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                                    DBG_PRINT("UserHookMgr_InjectShellcode: [WARN] ordinal import from %s, skip\n",
                                        importDllName);
                                    iat32->u1.Function = 0;
                                    failedCount++;
                                } else {
                                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(
                                        (PUCHAR)mappedBase
                                        + (hint32->u1.AddressOfData & ~IMAGE_ORDINAL_FLAG32));
                                    PVOID funcAddr = Utils_GetModuleExportAddress(
                                        Process, importBase, ibn->Name);
                                    if (!funcAddr) {
                                        DBG_PRINT("UserHookMgr_InjectShellcode: [WARN] export not found:"
                                                  " %s!%s\n", importDllName, ibn->Name);
                                        failedCount++;
                                    } else {
                                        resolvedCount++;
                                    }
                                    iat32->u1.Function = (ULONG)(ULONG_PTR)funcAddr;
                                }
                            }
                        } else {
                            // PE32+: 64-bit thunk data
                            PIMAGE_THUNK_DATA64 iat64 = (PIMAGE_THUNK_DATA64)(
                                (PUCHAR)mappedBase + importDesc->FirstThunk);
                            PIMAGE_THUNK_DATA64 hint64 = importDesc->OriginalFirstThunk
                                ? (PIMAGE_THUNK_DATA64)((PUCHAR)mappedBase
                                                         + importDesc->OriginalFirstThunk)
                                : iat64;
                            for (; hint64->u1.AddressOfData != 0; iat64++, hint64++) {
                                if (hint64->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                    DBG_PRINT("UserHookMgr_InjectShellcode: [WARN] ordinal import from %s, skip\n",
                                        importDllName);
                                    iat64->u1.Function = 0;
                                    failedCount++;
                                } else {
                                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(
                                        (PUCHAR)mappedBase
                                        + (hint64->u1.AddressOfData & ~IMAGE_ORDINAL_FLAG64));
                                    PVOID funcAddr = Utils_GetModuleExportAddress(
                                        Process, importBase, ibn->Name);
                                    if (!funcAddr) {
                                        DBG_PRINT("UserHookMgr_InjectShellcode: [WARN] export not found:"
                                                  " %s!%s\n", importDllName, ibn->Name);
                                        failedCount++;
                                    } else {
                                        resolvedCount++;
                                    }
                                    iat64->u1.Function = (ULONGLONG)funcAddr;
                                }
                            }
                        }
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
                        DBG_PRINT("UserHookMgr_InjectShellcode: %s resolved=%lu failed=%lu\n",
                            importDllName, resolvedCount, failedCount);
#endif
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DBG_PRINT("UserHookMgr_InjectShellcode: exception fixing imports (0x%08X)\n",
                        status);
                }
                KeUnstackDetachProcess(&apcState);
                if (!NT_SUCCESS(status)) goto Cleanup;
                DBG_PRINT("UserHookMgr_InjectShellcode: import table fixed\n");
            }
        }

        // ---- 7b. 查找 RtlAddFunctionTable（注册手动映射 DLL 的异常目录，避免 DLL 内异常导致进程崩溃）----
        // x64 进程专用；WoW64(x86) 进程异常处理机制不同，跳过此步骤
        ULONG_PTR rtlAddFunctionTableAddr = 0;
        ULONG_PTR pExcDirAddr = 0;
        ULONG     nExcEntries = 0;
        if (!isPE32) {
            if (excDir.VirtualAddress != 0 && excDir.Size > 0) {
                pExcDirAddr = (ULONG_PTR)mappedBase + excDir.VirtualAddress;
                nExcEntries = excDir.Size / 12; // sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)
            }

            if (pExcDirAddr != 0 && nExcEntries > 0) {
                KeStackAttachProcess((PRKPROCESS)Process, &apcState);
                UNICODE_STRING ntdllNameRtl;
                RtlInitUnicodeString(&ntdllNameRtl, L"ntdll.dll");
                // RtlAddFunctionTable 在 64-bit ntdll（非 WoW64 32-bit ntdll）
                PVOID ntdllBaseRtl = Utils_GetUserModuleBase(Process, &ntdllNameRtl, FALSE /* native 64-bit */);
                if (ntdllBaseRtl) {
                    rtlAddFunctionTableAddr = (ULONG_PTR)Utils_GetModuleExportAddress(
                        Process, ntdllBaseRtl, "RtlAddFunctionTable");
                }
                KeUnstackDetachProcess(&apcState);
            }

            DBG_PRINT("UserHookMgr_InjectShellcode: RtlAddFunctionTable=0x%llX "
                      "pExcDir=0x%llX nEntries=%lu\n",
                (ULONG64)rtlAddFunctionTableAddr, (ULONG64)pExcDirAddr, nExcEntries);
        }

        // ---- 8. 构造 Stub，通过 ZwCreateThreadEx 同步执行 DllMain ----
        ULONG_PTR dllMainAddr = (ULONG_PTR)mappedBase + addressOfEntryPoint;
        DBG_PRINT("UserHookMgr_InjectShellcode: DllMain=0x%llX\n", (ULONG64)dllMainAddr);

        PVOID  stubBase = NULL;
        SIZE_T stubSize = 88;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        status = ZwAllocateVirtualMemory(NtCurrentProcess(), &stubBase, 0, &stubSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        KeUnstackDetachProcess(&apcState);
        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: stub alloc failed (0x%08X)\n", status);
            goto Cleanup;
        }

        UCHAR  stubCode[88] = { 0 };
        SIZE_T writeStubSize;

        if (isPE32) {
            // ---- x86 Stub (32-bit)：调用 DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL) ----
            // 线程入口由 WoW64 层以 32 位模式调用，签名 DWORD WINAPI f(LPVOID)
            //
            //   [0x00] push 0              ; lpvReserved = NULL
            //   [0x02] push 1              ; fdwReason = DLL_PROCESS_ATTACH
            //   [0x04] push <mappedBase>   ; hinstDLL
            //   [0x09] mov eax, <dllMain>
            //   [0x0E] call eax
            //   [0x10] ret 4               ; stdcall: 清理 LPVOID 参数
            ULONG stubOff = 0;
            stubCode[stubOff++] = 0x6A; stubCode[stubOff++] = 0x00;              // push 0
            stubCode[stubOff++] = 0x6A; stubCode[stubOff++] = 0x01;              // push 1
            stubCode[stubOff++] = 0x68;                                           // push imm32
            *(ULONG*)(stubCode + stubOff) = (ULONG)(ULONG_PTR)mappedBase;
            stubOff += 4;
            stubCode[stubOff++] = 0xB8;                                           // mov eax, imm32
            *(ULONG*)(stubCode + stubOff) = (ULONG)dllMainAddr;
            stubOff += 4;
            stubCode[stubOff++] = 0xFF; stubCode[stubOff++] = 0xD0;              // call eax
            stubCode[stubOff++] = 0xC2;                                           // ret imm16
            *(USHORT*)(stubCode + stubOff) = 4;                                   // 清理 1 个 DWORD 参数
            stubOff += 2;
            writeStubSize = stubOff;  // 19 bytes
            DBG_PRINT("UserHookMgr_InjectShellcode: using %zu-byte x86 stub\n", writeStubSize);
        } else if (rtlAddFunctionTableAddr && pExcDirAddr && nExcEntries > 0) {
            // 88 字节 Stub（x64）：
            //   [0x00] sub rsp, 0x28
            //   [0x04] mov rcx, pExcDirAddr          ; PRUNTIME_FUNCTION
            //   [0x0E] mov edx, nExcEntries           ; EntryCount
            //   [0x13] mov r8,  mappedBase            ; BaseAddress
            //   [0x1D] call [rip+0x25]  -> [0x48]    ; RtlAddFunctionTable
            //   [0x23] mov rcx, mappedBase            ; hinstDLL
            //   [0x2D] mov edx, 1                    ; DLL_PROCESS_ATTACH
            //   [0x32] xor r8, r8                    ; lpvReserved=NULL
            //   [0x35] call [rip+0x15]  -> [0x50]    ; DllMain
            //   [0x3B] add rsp, 0x28
            //   [0x3F] ret
            //   [0x48] qword RtlAddFunctionTable
            //   [0x50] qword DllMain
            stubCode[0x00]=0x48; stubCode[0x01]=0x83; stubCode[0x02]=0xEC; stubCode[0x03]=0x28; // sub rsp,0x28
            stubCode[0x04]=0x48; stubCode[0x05]=0xB9;                                            // mov rcx,imm64
            *(ULONG_PTR*)(stubCode+0x06) = pExcDirAddr;
            stubCode[0x0E]=0xBA;                                                                  // mov edx,imm32
            *(ULONG*)(stubCode+0x0F) = nExcEntries;
            stubCode[0x13]=0x49; stubCode[0x14]=0xB8;                                            // mov r8,imm64
            *(ULONG_PTR*)(stubCode+0x15) = (ULONG_PTR)mappedBase;
            stubCode[0x1D]=0xFF; stubCode[0x1E]=0x15;                                            // call [rip+rel32]
            *(LONG*)(stubCode+0x1F) = 0x25;                                          // rip=0x23, 0x23+0x25=0x48
            stubCode[0x23]=0x48; stubCode[0x24]=0xB9;                                            // mov rcx,imm64
            *(ULONG_PTR*)(stubCode+0x25) = (ULONG_PTR)mappedBase;
            stubCode[0x2D]=0xBA; stubCode[0x2E]=0x01;                                            // mov edx,1
            stubCode[0x32]=0x4D; stubCode[0x33]=0x31; stubCode[0x34]=0xC0;                      // xor r8,r8
            stubCode[0x35]=0xFF; stubCode[0x36]=0x15;                                            // call [rip+rel32]
            *(LONG*)(stubCode+0x37) = 0x15;                                          // rip=0x3B, 0x3B+0x15=0x50
            stubCode[0x3B]=0x48; stubCode[0x3C]=0x83; stubCode[0x3D]=0xC4; stubCode[0x3E]=0x28; // add rsp,0x28
            stubCode[0x3F]=0xC3;                                                                  // ret
            *(ULONG_PTR*)(stubCode+0x48) = rtlAddFunctionTableAddr;
            *(ULONG_PTR*)(stubCode+0x50) = dllMainAddr;
            writeStubSize = 88;
            DBG_PRINT("UserHookMgr_InjectShellcode: using 88-byte x64 stub with RtlAddFunctionTable\n");
        } else {
            // 64 字节回退 Stub（x64）：仅调用 DllMain（无异常表注册）
            stubCode[0x00]=0x48; stubCode[0x01]=0x83; stubCode[0x02]=0xEC; stubCode[0x03]=0x28;
            stubCode[0x04]=0x48; stubCode[0x05]=0xB9;
            *(ULONG_PTR*)(stubCode+0x06) = (ULONG_PTR)mappedBase;
            stubCode[0x0E]=0xBA; stubCode[0x0F]=0x01;                                            // mov edx,1
            stubCode[0x13]=0x4D; stubCode[0x14]=0x31; stubCode[0x15]=0xC0;                      // xor r8,r8
            stubCode[0x16]=0xFF; stubCode[0x17]=0x15;
            *(LONG*)(stubCode+0x18) = 0x0A;                                          // rip=0x1C, 0x1C+0x0A=0x26
            stubCode[0x1C]=0x48; stubCode[0x1D]=0x83; stubCode[0x1E]=0xC4; stubCode[0x1F]=0x28;
            stubCode[0x20]=0xC3;
            *(ULONG_PTR*)(stubCode+0x26) = dllMainAddr;
            writeStubSize = 64;
            DBG_PRINT("UserHookMgr_InjectShellcode: using 64-byte x64 fallback stub\n");
        }

        status = UserHookMgr_WriteProcessMemory(Process, stubBase, stubCode, writeStubSize);
        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: stub write failed (0x%08X)\n", status);
            KeStackAttachProcess((PRKPROCESS)Process, &apcState);
            PVOID fb = stubBase; SIZE_T fs = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &fb, &fs, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            goto Cleanup;
        }

        // ---- ZwCreateThreadEx：在目标进程创建线程同步执行 DllMain ----
        // 懒加载 SSDT：UserHookMgr_Initialize 时 SyscallHook 尚未初始化 SSDT，
        // 等到首次注入时 SSDT 已就绪，在此补充通过 SSDT 解析 ZwCreateThreadEx。
        if (!g_ZwCreateThreadEx && g_KeServiceDescriptorTable) {
            ULONG ssdt_idx = Utils_GetSSDTIndex("ZwCreateThreadEx");
            if (ssdt_idx != (ULONG)-1) {
                g_ZwCreateThreadEx = (PFN_ZwCreateThreadEx)Utils_GetSSDTFunctionAddress(ssdt_idx);
                DBG_PRINT("UserHookMgr_InjectShellcode: ZwCreateThreadEx via SSDT index=%lu addr=%p\n",
                    ssdt_idx, g_ZwCreateThreadEx);
            }
        }

        if (!g_ZwCreateThreadEx) {
            DBG_PRINT("UserHookMgr_InjectShellcode: ZwCreateThreadEx 不可用，注入失败\n");
            KeStackAttachProcess((PRKPROCESS)Process, &apcState);
            PVOID fb = stubBase; SIZE_T fs = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &fb, &fs, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            status = STATUS_NOT_SUPPORTED;
            goto Cleanup;
        }

        HANDLE procHandle = NULL;
        status = ObOpenObjectByPointer(
            Process, OBJ_KERNEL_HANDLE, NULL,
            PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: ObOpenObjectByPointer failed (0x%08X)\n", status);
            KeStackAttachProcess((PRKPROCESS)Process, &apcState);
            PVOID fb = stubBase; SIZE_T fs = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &fb, &fs, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            goto Cleanup;
        }

        HANDLE threadHandle = NULL;
        {
            KPROCESSOR_MODE oldMode = SetCurrentThreadPreviousModeKernel();
            status = g_ZwCreateThreadEx(
                &threadHandle, THREAD_ALL_ACCESS, NULL, procHandle,
                (PVOID)stubBase, NULL,
                0,   // CreateFlags: 0 = 立即运行（非挂起）
                0, 0, 0, NULL);
            RestoreCurrentThreadPreviousMode(oldMode);
        }
        ZwClose(procHandle);

        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: ZwCreateThreadEx failed (0x%08X)\n", status);
            KeStackAttachProcess((PRKPROCESS)Process, &apcState);
            PVOID fb = stubBase; SIZE_T fs = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &fb, &fs, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            goto Cleanup;
        }

        DBG_PRINT("UserHookMgr_InjectShellcode: Thread created, waiting for DllMain completion...\n");

        // 同步等待线程退出（= DllMain 执行完毕），最长 10 秒
        LARGE_INTEGER threadTimeout;
        threadTimeout.QuadPart = -100000000LL;  // -10s（相对时间，单位 100ns）

        NTSTATUS waitStatus = ZwWaitForSingleObject(threadHandle, FALSE, &threadTimeout);
        ZwClose(threadHandle);

        if (waitStatus == STATUS_TIMEOUT) {
            DBG_PRINT("UserHookMgr_InjectShellcode: DllMain 线程超时（10s），"
                "Hook 可能尚未安装\n");
        } else if (NT_SUCCESS(waitStatus)) {
            DBG_PRINT("UserHookMgr_InjectShellcode: DllMain 线程已退出，"
                "Hook 安装完成\n");
        } else {
            DBG_PRINT("UserHookMgr_InjectShellcode: ZwWaitForSingleObject failed (0x%08X)\n",
                waitStatus);
        }

        DBG_PRINT("UserHookMgr_InjectShellcode: ManualMap OK base=%p, stub=%p\n",
            mappedBase, stubBase);

        HookInfo->ShellcodeBaseUser = mappedBase;
        HookInfo->ShellcodeSize     = sizeOfImage;
        HookInfo->TrampolineAddr    = NULL;   // DLL 内部自行管理 Trampoline
        HookInfo->DeviceHandle      = NULL;   // DLL 自行打开设备
    }

    ExFreePoolWithTag(fileBuffer, 'lliD');
    return STATUS_SUCCESS;

Cleanup:
    ExFreePoolWithTag(fileBuffer, 'lliD');
    if (mappedBase) {
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        PVOID fb = mappedBase; SIZE_T fs = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(), &fb, &fs, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
    }
    return status;
}



static NTSTATUS UserHookMgr_PatchOriginalFunction(
    _In_ PEPROCESS Process,
    _Inout_ PPROCESS_HOOK_INFO HookInfo
)
{
    NTSTATUS status;
    KAPC_STATE apcState;

    // 构造跳转指令: FF 25 00 00 00 00 [8字节地址]
    UCHAR jumpCode[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 地址
    };

    // 填充Shellcode跳转目标
    *(PVOID*)(jumpCode + 6) = HookInfo->ShellcodeBaseUser;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try {
        // 修改内存保护
        PVOID targetAddr = HookInfo->OriginalFuncAddr;
        SIZE_T regionSize = sizeof(jumpCode);
        ULONG oldProtect = 0;

        status = ZwProtectVirtualMemory(
            NtCurrentProcess(),
            &targetAddr,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            DBG_PRINT("UserHookMgr_PatchOriginalFunction: ZwProtectVirtualMemory failed (0x%08X)\n",
                status);
            __leave;
        }

        // 写入跳转指令
        RtlCopyMemory(HookInfo->OriginalFuncAddr, jumpCode, sizeof(jumpCode));

        // 恢复原始保护属性
        targetAddr = HookInfo->OriginalFuncAddr;
        regionSize = sizeof(jumpCode);

        ZwProtectVirtualMemory(
            NtCurrentProcess(),
            &targetAddr,
            &regionSize,
            oldProtect,
            &oldProtect
        );

        status = STATUS_SUCCESS;

        DBG_PRINT("UserHookMgr_PatchOriginalFunction: Patched KiUserExceptionDispatcher\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DBG_PRINT("UserHookMgr_PatchOriginalFunction: Exception (0x%08X)\n", status);
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}

static NTSTATUS UserHookMgr_RestoreOriginalFunction(
    _In_ PEPROCESS Process,
    _In_ PPROCESS_HOOK_INFO HookInfo
)
{
    NTSTATUS status;
    KAPC_STATE apcState;

    if (!HookInfo->OriginalFuncAddr || HookInfo->OriginalBytesSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try {
        PVOID targetAddr = HookInfo->OriginalFuncAddr;
        SIZE_T regionSize = HookInfo->OriginalBytesSize;
        ULONG oldProtect = 0;

        status = ZwProtectVirtualMemory(
            NtCurrentProcess(),
            &targetAddr,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            __leave;
        }

        // 恢复原始字节
        RtlCopyMemory(HookInfo->OriginalFuncAddr, HookInfo->OriginalBytes,
            HookInfo->OriginalBytesSize);

        // 恢复保护
        targetAddr = HookInfo->OriginalFuncAddr;
        regionSize = HookInfo->OriginalBytesSize;

        ZwProtectVirtualMemory(
            NtCurrentProcess(),
            &targetAddr,
            &regionSize,
            oldProtect,
            &oldProtect
        );

        status = STATUS_SUCCESS;

        DBG_PRINT("UserHookMgr_RestoreOriginalFunction: Restored original bytes\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}

// ============================================================================
// 公开API实现
// ============================================================================

NTSTATUS UserHookMgr_InstallHook(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime
)
{
    NTSTATUS status;

    if (!g_UserHookMgrInitialized) {
        DBG_PRINT("UserHookMgr_InstallHook: Not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 查找或创建进程节点
    BOOLEAN wasCreated = FALSE;
    PPROCESS_NODE processNode = DataManager_FindOrCreateProcess(
        ProcessId,
        ProcessCreateTime,
        &wasCreated
    );

    if (!processNode) {
        DBG_PRINT("UserHookMgr_InstallHook: Failed to get process node\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 检测是否已安装Hook
    if (processNode->IsHookInstalled) {
        DBG_PRINT("UserHookMgr_InstallHook: Hook already installed for PID %lu\n",
            (ULONG)(ULONG_PTR)ProcessId);
        DataManager_ReleaseProcess(processNode);
        return STATUS_SUCCESS;
    }

    // 获取EPROCESS
    PEPROCESS process = NULL;
    status = PsLookupProcessByProcessId(ProcessId, &process);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("UserHookMgr_InstallHook: PsLookupProcessByProcessId failed (0x%08X)\n", status);
        DataManager_ReleaseProcess(processNode);
        return status;
    }

    // 检测是否为WoW64进程（32位进程运行于64位系统）
    // WoW64 进程的硬件异常（DEP 故障）分发完全绕过 32 位 KiUED，
    // 因此 32 位 DLL 的 KiUED Hook 无法捕获 DEP 违例。
    // 跳过 Hook 安装，改由进程退出回调中的崩溃检测覆盖。
    BOOLEAN isWow64 = (PsGetProcessWow64Process(process) != NULL);

    if (isWow64) {
        PCHAR procName = (PCHAR)PsGetProcessImageFileName(process);
        PCSTR safeName = (procName && procName[0]) ? procName : "Unknown";
        DBG_PRINT("UserHookMgr_InstallHook: WoW64 进程 PID=%lu (%s)，跳过 Hook（硬件异常绕过 32 位 KiUED）\n",
            (ULONG)(ULONG_PTR)ProcessId, safeName);

        CHAR args[128];
        _snprintf_s(args, sizeof(args), _TRUNCATE,
            "PID=%lu Name=%s", (ULONG)(ULONG_PTR)ProcessId, safeName);
        FileLogger_LogEvent("WOW64_SKIP", args);

        ObDereferenceObject(process);
        DataManager_ReleaseProcess(processNode);
        return STATUS_NOT_SUPPORTED;
    }

    // 准备Hook信息
    PROCESS_HOOK_INFO hookInfo;
    status = UserHookMgr_PrepareHookInfo(process, isWow64, &hookInfo);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        DataManager_ReleaseProcess(processNode);
        return status;
    }

    hookInfo.State = HookStateInstalling;

    // 注入 DLL（Kernel Manual Map + ZwCreateThreadEx 调用初始化入口）
    // DllMain 负责安装 KiUserExceptionDispatcher Hook，内核不再调用 PatchOriginalFunction
    status = UserHookMgr_InjectShellcode(process, &hookInfo);

    if (!NT_SUCCESS(status)) {
        hookInfo.State = HookStateFailed;
        ObDereferenceObject(process);
        DataManager_ReleaseProcess(processNode);
        return status;
    }

    hookInfo.State = HookStateInstalled;

    // 更新进程节点
    DataManager_SetProcessHooked(
        processNode,
        hookInfo.ShellcodeBaseUser,
        hookInfo.ShellcodeSize,
        hookInfo.TrampolineAddr,
        hookInfo.DeviceHandle
    );

    // 保存 KiUED 地址（供 IOCTL_HIDE_MODULE 处理时启用 Hook 保护）
    ExAcquirePushLockExclusive(&processNode->NodeLock);
    processNode->KiUedAddress = hookInfo.OriginalFuncAddr;
    ExReleasePushLockExclusive(&processNode->NodeLock);

    ObDereferenceObject(process);

    // ZwCreateThreadEx 同步等待线程结束（= DllMain 完成 + KiUED Hook 已安装），
    // 无需额外的 DllReadyEvent 等待。

    DataManager_ReleaseProcess(processNode);

    // HOOK_INSTALL 事件日志
    {
        CHAR _hName[16], hArgs[256];
        PCHAR rawName = Utils_GetProcessNameByPid(ProcessId);
        if (rawName) {
            SIZE_T nLen = 0;
            while (nLen < 15 && rawName[nLen]) nLen++;
            RtlCopyMemory(_hName, rawName, nLen);
            _hName[nLen] = '\0';
        } else {
            _hName[0] = '?'; _hName[1] = '\0';
        }
        _snprintf_s(hArgs, sizeof(hArgs), _TRUNCATE,
            "PID=%lu Name=%s KiUED=%p DllBase=%p DllSize=0x%zX Method=ZwCreateThreadEx",
            (ULONG)(ULONG_PTR)ProcessId, _hName,
            hookInfo.OriginalFuncAddr,
            hookInfo.ShellcodeBaseUser,
            hookInfo.ShellcodeSize);
        FileLogger_LogEvent("HOOK_INSTALL", hArgs);
    }

    DBG_PRINT("UserHookMgr_InstallHook: Successfully installed hook for PID %lu\n",
        (ULONG)(ULONG_PTR)ProcessId);

    return STATUS_SUCCESS;
}

NTSTATUS UserHookMgr_RemoveHook(
    _In_ HANDLE ProcessId
)
{
    if (!g_UserHookMgrInitialized) {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS_NODE processNode = DataManager_FindProcess(ProcessId);

    if (!processNode || !processNode->IsHookInstalled) {
        if (processNode) {
            DataManager_ReleaseProcess(processNode);
        }
        return STATUS_NOT_FOUND;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (!NT_SUCCESS(status)) {
        DataManager_ReleaseProcess(processNode);
        return status;
    }

    // 构造临时HookInfo用于恢复
    PROCESS_HOOK_INFO hookInfo = { 0 };
    hookInfo.Process = process;
    hookInfo.ProcessId = ProcessId;
    hookInfo.ShellcodeBaseUser = processNode->ShellcodeBase;
    hookInfo.ShellcodeSize = processNode->ShellcodeSize;
    hookInfo.TrampolineAddr = processNode->TrampolineAddr;
    hookInfo.DeviceHandle = processNode->DeviceHandle;

    // 获取原始函数地址
    BOOLEAN isWow64 = (PsGetProcessWow64Process(process) != NULL);

    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    hookInfo.OriginalFuncAddr = UserHookMgr_GetKiUserExceptionDispatcher(process, isWow64);
    KeUnstackDetachProcess(&apcState);

    // 从Trampoline读取原始字节
    if (hookInfo.TrampolineAddr) {
        status = UserHookMgr_ReadProcessMemory(
            process,
            hookInfo.TrampolineAddr,
            hookInfo.OriginalBytes,
            14  // 至少读取跳转指令大小
        );

        if (NT_SUCCESS(status)) {
            hookInfo.OriginalBytesSize = 14; // Hook size is always 14 bytes (FF25 absolute jmp)

            // 恢复原始函数
            status = UserHookMgr_RestoreOriginalFunction(process, &hookInfo);
        }
    }

    // 释放Shellcode内存，关闭用户态设备句柄
    if (hookInfo.ShellcodeBaseUser) {
        KAPC_STATE freeApc;
        KeStackAttachProcess((PRKPROCESS)process, &freeApc);
        PVOID freeBase = hookInfo.ShellcodeBaseUser;
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(), &freeBase, &freeSize, MEM_RELEASE);
        if (hookInfo.DeviceHandle) {
            ZwClose(hookInfo.DeviceHandle);
        }
        KeUnstackDetachProcess(&freeApc);
        DBG_PRINT("UserHookMgr_RemoveHook: Freed shellcode memory and closed device handle\n");
    }

    ObDereferenceObject(process);
    DataManager_ReleaseProcess(processNode);

    DBG_PRINT("UserHookMgr_RemoveHook: Removed hook from PID %lu (0x%08X)\n",
        (ULONG)(ULONG_PTR)ProcessId, status);

    return status;
}

BOOLEAN UserHookMgr_IsHookInstalled(
    _In_ HANDLE ProcessId
)
{
    PPROCESS_NODE processNode = DataManager_FindProcess(ProcessId);

    if (!processNode) {
        return FALSE;
    }

    BOOLEAN result = processNode->IsHookInstalled;
    DataManager_ReleaseProcess(processNode);

    return result;
}

// ============================================================================
// 异常处理实现
// ============================================================================

NTSTATUS UserHookMgr_HandleException(
    _In_ PEXCEPTION_REPORT_PACKET Report,
    _Out_ PEXCEPTION_RESPONSE_PACKET Response
)
{
    if (!Report || !Response) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Response, sizeof(EXCEPTION_RESPONSE_PACKET));

    DBG_PRINT("UserHookMgr_HandleException: PID=%lu, TID=%lu, FaultAddr=%p\n",
        Report->ProcessId, Report->ThreadId, (PVOID)Report->FaultAddress);

    // 查找受控区域快照，避免在释放 AVL 锁后继续使用节点裸指针
    MEMORY_REGION_NODE regionSnapshot = { 0 };
    if (!DataManager_QueryMemoryRegionSnapshot(
        (HANDLE)(ULONG_PTR)Report->ProcessId,
        Report->FaultAddress,
        &regionSnapshot))
    {
        // 这不是我们控制的内存区域
        DBG_PRINT("UserHookMgr_HandleException: Memory region not found, passing through\n");

        Response->Status = STATUS_NOT_FOUND;
        Response->Action = EXCEPTION_ACTION_PASSTHROUGH;
        return STATUS_SUCCESS;
    }

    DBG_PRINT("UserHookMgr_HandleException: Found controlled region [%p-%p)\n",
        (PVOID)regionSnapshot.StartAddress, (PVOID)regionSnapshot.EndAddress);
    DBG_PRINT("  OriginalProtection = %s, InitiatorPid = %lu\n",
        ProtectionToString(regionSnapshot.OriginalProtection),
        (ULONG)(ULONG_PTR)regionSnapshot.InitiatorPid);

    // 记录日志
    SHELLCODE_LOG_ENTRY logEntry = { 0 };
    KeQuerySystemTime(&logEntry.Timestamp);
    logEntry.ProcessId = Report->ProcessId;
    logEntry.ThreadId = Report->ThreadId;
    logEntry.FaultAddress = Report->FaultAddress;
    logEntry.BaseAddress = regionSnapshot.StartAddress;
    logEntry.RegionSize = regionSnapshot.EndAddress - regionSnapshot.StartAddress;
    logEntry.OriginalProtection = regionSnapshot.OriginalProtection;
    logEntry.InitiatorPid = (ULONG)(ULONG_PTR)regionSnapshot.InitiatorPid;

    // 获取进程名
    PCHAR processName = Utils_GetProcessNameByPid((HANDLE)(ULONG_PTR)Report->ProcessId);
    PCHAR initiatorName = Utils_GetProcessNameByPid(regionSnapshot.InitiatorPid);

    if (processName) {
        RtlStringCbCopyA(logEntry.ProcessName, sizeof(logEntry.ProcessName), processName);
    }
    if (initiatorName) {
        RtlStringCbCopyA(logEntry.InitiatorName, sizeof(logEntry.InitiatorName), initiatorName);
    }

    DataManager_AddLogEntry(&logEntry);

    // EXCEPTION_REPORT 事件日志
    {
        CHAR eArgs[300];
        _snprintf_s(eArgs, sizeof(eArgs), _TRUNCATE,
            "PID=%lu Name=%s TID=%lu FaultAddr=%08llX "
            "RegionStart=%08llX RegionEnd=%08llX OrigProt=%s SrcPID=%lu Action=CONTINUE",
            Report->ProcessId,
            logEntry.ProcessName[0] ? logEntry.ProcessName : "?",
            Report->ThreadId,
            (ULONG64)Report->FaultAddress,
            (ULONG64)regionSnapshot.StartAddress,
            (ULONG64)regionSnapshot.EndAddress,
            ProtectionToString(regionSnapshot.OriginalProtection),
            (ULONG)(ULONG_PTR)regionSnapshot.InitiatorPid);
        FileLogger_LogEvent("EXCEPTION_REPORT", eArgs);
    }

    // 恢复原始内存保护权限，允许执行
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Report->ProcessId, &process);

    if (NT_SUCCESS(status)) {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)process, &apcState);

        __try {
            PVOID targetAddr = (PVOID)regionSnapshot.StartAddress;
            SIZE_T regionSize = regionSnapshot.EndAddress - regionSnapshot.StartAddress;
            ULONG oldProtect = 0;

            status = ZwProtectVirtualMemory(
                NtCurrentProcess(),
                &targetAddr,
                &regionSize,
                regionSnapshot.OriginalProtection,
                &oldProtect
            );

            if (NT_SUCCESS(status)) {
                DBG_PRINT("UserHookMgr_HandleException: Restored protection to %s\n",
                    ProtectionToString(regionSnapshot.OriginalProtection));

                // 更新当前保护属性
                ULONG newProt = regionSnapshot.OriginalProtection;
                PPROCESS_NODE processNode = DataManager_FindProcess((HANDLE)(ULONG_PTR)Report->ProcessId);
                if (processNode) {
                    DataManager_UpdateMemoryRegion(
                        processNode,
                        regionSnapshot.StartAddress,
                        &newProt,
                        NULL,
                        NULL,
                        NULL
                    );
                    DataManager_ReleaseProcess(processNode);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DBG_PRINT("UserHookMgr_HandleException: Exception restoring protection (0x%08X)\n",
                status);
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
    }

    if (NT_SUCCESS(status)) {
        Response->Status = STATUS_SUCCESS;
        Response->Action = EXCEPTION_ACTION_CONTINUE;
        Response->NewProtection = regionSnapshot.OriginalProtection;
    }
    else {
        Response->Status = status;
        Response->Action = EXCEPTION_ACTION_PASSTHROUGH;
    }

    return STATUS_SUCCESS;
}
