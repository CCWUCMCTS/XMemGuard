// ============================================================================
// Utils.cpp - 工具库实现
// ============================================================================

#include "Utils.hpp"
#include "refs.hpp"
#include <ntstrsafe.h>

// Local LDR entry struct for L1/L4 module unlinking (has all three link lists)
typedef struct _HIDE_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} HIDE_LDR_ENTRY, *PHIDE_LDR_ENTRY;

// ============================================================================
// 全局变量
// ============================================================================

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable = NULL;

// ============================================================================
// LDE (Length Disassembly Engine) 实现
// 这是一个简化的x64指令长度反汇编器
// ============================================================================

// x64指令前缀
#define PREFIX_OPERAND_SIZE     0x66
#define PREFIX_ADDRESS_SIZE     0x67
#define PREFIX_LOCK             0xF0
#define PREFIX_REPNE            0xF2
#define PREFIX_REP              0xF3
#define PREFIX_SEG_CS           0x2E
#define PREFIX_SEG_SS           0x36
#define PREFIX_SEG_DS           0x3E
#define PREFIX_SEG_ES           0x26
#define PREFIX_SEG_FS           0x64
#define PREFIX_SEG_GS           0x65

// REX前缀范围
#define REX_PREFIX_START        0x40
#define REX_PREFIX_END          0x4F

// VEX前缀
#define VEX_2BYTE               0xC5
#define VEX_3BYTE               0xC4

// 操作码映射表类型
typedef enum _OPCODE_TYPE {
    OP_NONE = 0,        // 无操作数
    OP_MODRM,           // 有ModR/M字节
    OP_MODRM_IMM8,      // ModR/M + 8位立即数
    OP_MODRM_IMM32,     // ModR/M + 32位立即数
    OP_IMM8,            // 8位立即数
    OP_IMM16,           // 16位立即数
    OP_IMM32,           // 32位立即数
    OP_IMM64,           // 64位立即数
    OP_REL8,            // 8位相对地址
    OP_REL32,           // 32位相对地址
    OP_MOFFS,           // 内存偏移
    OP_PREFIX,          // 前缀
    OP_INVALID          // 无效
} OPCODE_TYPE;

// 单字节操作码表 (简化版)
static const UCHAR g_OpcodeTable[256] = {
    // 0x00-0x0F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    // 0x10-0x1F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    // 0x20-0x2F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    // 0x30-0x3F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    // 0x40-0x4F (REX前缀在x64中)
    OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    // 0x50-0x5F (PUSH/POP)
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0x60-0x6F
    OP_INVALID, OP_INVALID, OP_INVALID, OP_MODRM, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    OP_IMM32, OP_MODRM_IMM32, OP_IMM8, OP_MODRM_IMM8, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0x70-0x7F (Jcc短跳转)
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
    // 0x80-0x8F
    OP_MODRM_IMM8, OP_MODRM_IMM32, OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x90-0x9F
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xA0-0xAF
    OP_MOFFS, OP_MOFFS, OP_MOFFS, OP_MOFFS, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_IMM8, OP_IMM32, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xB0-0xBF
    OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
    OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64,
    // 0xC0-0xCF
    OP_MODRM_IMM8, OP_MODRM_IMM8, OP_IMM16, OP_NONE, OP_INVALID, OP_INVALID, OP_MODRM_IMM8, OP_MODRM_IMM32,
    OP_IMM16, OP_NONE, OP_IMM16, OP_NONE, OP_NONE, OP_IMM8, OP_INVALID, OP_NONE,
    // 0xD0-0xDF
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM8, OP_INVALID, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xE0-0xEF
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
    OP_REL32, OP_REL32, OP_MOFFS, OP_REL8, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xF0-0xFF
    OP_PREFIX, OP_INVALID, OP_PREFIX, OP_PREFIX, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM
};

// 0F前缀操作码表 (简化版)
static const UCHAR g_Opcode0FTable[256] = {
    // 0x00-0x0F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_INVALID, OP_NONE, OP_INVALID, OP_MODRM, OP_NONE, OP_MODRM_IMM8,
    // 0x10-0x1F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x20-0x2F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x30-0x3F
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_INVALID, OP_NONE,
    OP_MODRM, OP_INVALID, OP_MODRM, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID,
    // 0x40-0x4F (CMOVcc)
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x50-0x5F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x60-0x6F
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x70-0x7F
    OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_NONE,
    OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x80-0x8F (Jcc长跳转)
    OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32,
    OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32,
    // 0x90-0x9F (SETcc)
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xA0-0xAF
    OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM_IMM8, OP_MODRM, OP_INVALID, OP_INVALID,
    OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM_IMM8, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xB0-0xBF
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_INVALID, OP_MODRM_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xC0-0xCF
    OP_MODRM, OP_MODRM, OP_MODRM_IMM8, OP_MODRM, OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM_IMM8, OP_MODRM,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xD0-0xDF
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xE0-0xEF
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xF0-0xFF
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID
};

// 解析ModR/M字节，返回额外长度 (SIB + displacement)
static ULONG ParseModRM(PUCHAR pCode, BOOLEAN hasAddressPrefix)
{
    ULONG length = 1;  // ModR/M字节本身
    UCHAR modrm = *pCode;
    UCHAR mod = (modrm >> 6) & 0x03;
    UCHAR rm = modrm & 0x07;

    // 检查是否需要SIB字节 (仅在非寄存器直接寻址时)
    if (mod != 3 && rm == 4) {
        length++;  // SIB字节
        UCHAR sib = *(pCode + 1);
        UCHAR base = sib & 0x07;

        // 特殊情况: mod=0, base=5 -> disp32
        if (mod == 0 && base == 5) {
            length += 4;
        }
    }

    // 计算displacement长度
    switch (mod) {
    case 0:
        // 特殊情况: rm=5 -> RIP相对寻址 (disp32)
        if (rm == 5) {
            length += 4;
        }
        break;
    case 1:
        length += 1;  // disp8
        break;
    case 2:
        length += 4;  // disp32
        break;
    case 3:
        // 寄存器直接寻址，无额外字节
        break;
    }

    UNREFERENCED_PARAMETER(hasAddressPrefix);
    return length;
}

ULONG LDE_GetInstructionLength(
    _In_ PVOID Address
)
{
    if (!Address) {
        return 0;
    }

    __try {
        PUCHAR pCode = (PUCHAR)Address;
        ULONG length = 0;
        BOOLEAN hasRex = FALSE;
        BOOLEAN hasOperandPrefix = FALSE;
        BOOLEAN hasAddressPrefix = FALSE;
        BOOLEAN has0F = FALSE;
        UCHAR rexByte = 0;

        // 1. 解析前缀
        while (TRUE) {
            UCHAR b = *pCode;

            // Legacy前缀
            if (b == PREFIX_OPERAND_SIZE) {
                hasOperandPrefix = TRUE;
                pCode++;
                length++;
            }
            else if (b == PREFIX_ADDRESS_SIZE) {
                hasAddressPrefix = TRUE;
                pCode++;
                length++;
            }
            else if (b == PREFIX_LOCK || b == PREFIX_REPNE || b == PREFIX_REP ||
                b == PREFIX_SEG_CS || b == PREFIX_SEG_SS || b == PREFIX_SEG_DS ||
                b == PREFIX_SEG_ES || b == PREFIX_SEG_FS || b == PREFIX_SEG_GS) {
                pCode++;
                length++;
            }
            // REX前缀 (0x40-0x4F)
            else if (b >= REX_PREFIX_START && b <= REX_PREFIX_END) {
                hasRex = TRUE;
                rexByte = b;
                pCode++;
                length++;
            }
            // VEX前缀 (简化处理)
            else if (b == VEX_2BYTE) {
                pCode += 2;
                length += 2;
                // VEX指令需要更复杂的处理，这里简化
            }
            else if (b == VEX_3BYTE) {
                pCode += 3;
                length += 3;
            }
            else {
                break;
            }
        }

        // 2. 解析操作码
        UCHAR opcode = *pCode;
        pCode++;
        length++;

        UCHAR opcodeType;

        // 检查是否是0F前缀操作码
        if (opcode == 0x0F) {
            has0F = TRUE;
            opcode = *pCode;
            pCode++;
            length++;

            // 检查0F 38/3A (3字节操作码)
            if (opcode == 0x38 || opcode == 0x3A) {
                pCode++;
                length++;
                opcodeType = OP_MODRM;  // 简化处理
                if (opcode == 0x3A) {
                    // 0F 3A xx 通常带一个立即数
                    opcodeType = OP_MODRM_IMM8;
                }
            }
            else {
                opcodeType = g_Opcode0FTable[opcode];
            }
        }
        else {
            opcodeType = g_OpcodeTable[opcode];
        }

        // 3. 根据操作码类型计算额外长度
        switch (opcodeType) {
        case OP_NONE:
            break;

        case OP_MODRM:
            length += ParseModRM(pCode, hasAddressPrefix);
            break;

        case OP_MODRM_IMM8:
            length += ParseModRM(pCode, hasAddressPrefix);
            length += 1;
            break;

        case OP_MODRM_IMM32:
            length += ParseModRM(pCode, hasAddressPrefix);
            length += hasOperandPrefix ? 2 : 4;
            break;

        case OP_IMM8:
        case OP_REL8:
            length += 1;
            break;

        case OP_IMM16:
            length += 2;
            break;

        case OP_IMM32:
        case OP_REL32:
            length += hasOperandPrefix ? 2 : 4;
            break;

        case OP_IMM64:
            // MOV r64, imm64 (REX.W)
            if (hasRex && (rexByte & 0x08)) {
                length += 8;
            }
            else {
                length += hasOperandPrefix ? 2 : 4;
            }
            break;

        case OP_MOFFS:
            // 内存偏移地址
            length += hasAddressPrefix ? 4 : 8;
            break;

        case OP_PREFIX:
            // 已经处理过了
            break;

        case OP_INVALID:
        default:
            DBG_PRINT("LDE_GetInstructionLength: Invalid opcode 0x%02X at %p\n",
                opcode, Address);
            return 0;
        }

#if DEBUG_MODE
        DBG_PRINT("LDE_GetInstructionLength: Address=%p, Length=%lu, Opcode=0x%02X%s\n",
            Address, length, opcode, has0F ? " (0F prefix)" : "");
#endif

        return length;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("LDE_GetInstructionLength: Exception at address %p\n", Address);
        return 0;
    }
}

ULONG LDE_CalculateTrampolineSize(
    _In_ PVOID Address,
    _In_ ULONG JmpSize
)
{
    if (!Address || JmpSize == 0) {
        return 0;
    }

    ULONG totalLength = 0;
    PUCHAR pCode = (PUCHAR)Address;

    while (totalLength < JmpSize) {
        ULONG instLen = LDE_GetInstructionLength(pCode);

        if (instLen == 0) {
            DBG_PRINT("LDE_CalculateTrampolineSize: Failed to parse instruction at %p\n", pCode);
            return 0;
        }

        totalLength += instLen;
        pCode += instLen;

        // 安全检查：防止无限循环
        if (totalLength > 64) {
            DBG_PRINT("LDE_CalculateTrampolineSize: Trampoline too long (>64 bytes)\n");
            return 0;
        }
    }

    DBG_PRINT("LDE_CalculateTrampolineSize: Address=%p, JmpSize=%lu, TotalLength=%lu\n",
        Address, JmpSize, totalLength);

    return totalLength;
}

// ============================================================================
// 内存操作工具实现
// ============================================================================

NTSTATUS Utils_SafeReadUserMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
)
{
    if (!SourceAddress || !Destination || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        ProbeForRead(SourceAddress, Length, 1);
        RtlCopyMemory(Destination, SourceAddress, Length);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_SafeReadUserMemory: Exception reading from %p\n", SourceAddress);
        return GetExceptionCode();
    }
}

NTSTATUS Utils_SafeWriteUserMemory(
    _In_ PVOID DestinationAddress,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
)
{
    if (!DestinationAddress || !Source || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        ProbeForWrite(DestinationAddress, Length, 1);
        RtlCopyMemory(DestinationAddress, Source, Length);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_SafeWriteUserMemory: Exception writing to %p\n", DestinationAddress);
        return GetExceptionCode();
    }
}

NTSTATUS Utils_WriteMemoryWithMdl(
    _In_ PVOID DestinationAddress,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
)
{
    if (!DestinationAddress || !Source || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        // 分配MDL
        mdl = IoAllocateMdl(DestinationAddress, (ULONG)Length, FALSE, FALSE, NULL);
        if (!mdl) {
            DBG_PRINT("Utils_WriteMemoryWithMdl: IoAllocateMdl failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // 锁定页面
        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DBG_PRINT("Utils_WriteMemoryWithMdl: MmProbeAndLockPages failed\n");
            IoFreeMdl(mdl);
            return GetExceptionCode();
        }

        // 映射到系统空间
        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            NULL,
            FALSE,
            NormalPagePriority
        );

        if (!mappedAddress) {
            DBG_PRINT("Utils_WriteMemoryWithMdl: MmMapLockedPagesSpecifyCache failed\n");
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_UNSUCCESSFUL;
        }

        // 写入数据
        RtlCopyMemory(mappedAddress, Source, Length);

        // 清理
        MmUnmapLockedPages(mappedAddress, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
        DBG_PRINT("Utils_WriteMemoryWithMdl: Successfully wrote %zu bytes to %p\n",
            Length, DestinationAddress);
#endif

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mappedAddress && mdl) {
            MmUnmapLockedPages(mappedAddress, mdl);
        }
        if (mdl) {
            __try {
                MmUnlockPages(mdl);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
            IoFreeMdl(mdl);
        }
        DBG_PRINT("Utils_WriteMemoryWithMdl: Exception occurred\n");
        return GetExceptionCode();
    }
}

NTSTATUS Utils_AllocateUserMemory(
    _In_ HANDLE ProcessHandle,
    _Out_ PVOID* BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG Protection
)
{
    if (!BaseAddress || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BaseAddress = NULL;
    SIZE_T regionSize = Size;

    NTSTATUS status = ZwAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        Protection
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Utils_AllocateUserMemory: Failed with status 0x%08X\n", status);
    }

    return status;
}

NTSTATUS Utils_FreeUserMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress
)
{
    if (!BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T regionSize = 0;

    NTSTATUS status = ZwFreeVirtualMemory(
        ProcessHandle,
        &BaseAddress,
        &regionSize,
        MEM_RELEASE
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Utils_FreeUserMemory: Failed with status 0x%08X\n", status);
    }

    return status;
}

// ============================================================================
// 进程工具实现
// ============================================================================

PCHAR Utils_GetProcessNameByPid(
    _In_ HANDLE ProcessId
)
{
    PEPROCESS process = NULL;
    PCHAR name = NULL;

    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status)) {
        name = (PCHAR)PsGetProcessImageFileName(process);
        ObDereferenceObject(process);
    }

    return name ? name : "Unknown";
}

NTSTATUS Utils_GetPidFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId,
    _Out_opt_ PLONGLONG CreateTime
)
{
    if (!ProcessId) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&process,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Utils_GetPidFromHandle: ObReferenceObjectByHandle failed (0x%08X)\n", status);
        return status;
    }

    *ProcessId = PsGetProcessId(process);

    if (CreateTime) {
        *CreateTime = PsGetProcessCreateTimeQuadPart(process);
    }

    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

NTSTATUS Utils_GetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
)
{
    if (!ParentProcessId) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *ParentProcessId = PsGetProcessInheritedFromUniqueProcessId(process);
    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

BOOLEAN Utils_AreParentChildProcesses(
    _In_ HANDLE ParentPid,
    _In_ HANDLE ChildPid
)
{
    HANDLE childParentPid = NULL;

    NTSTATUS status = Utils_GetParentProcessId(ChildPid, &childParentPid);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return (childParentPid == ParentPid);
}

PEPROCESS Utils_LookupProcessByPid(
    _In_ HANDLE ProcessId
)
{
    PEPROCESS process = NULL;

    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status)) {
        return process;
    }

    return NULL;
}

// ============================================================================
// 模块工具实现
// ============================================================================

PVOID Utils_GetUserModuleBase(
    _In_ PEPROCESS Process,
    _In_ PUNICODE_STRING ModuleName,
    _In_ BOOLEAN IsWow64
)
{
    if (!Process || !ModuleName) {
        return NULL;
    }

    __try {
        LARGE_INTEGER waitTime;
        waitTime.QuadPart = -250LL * 10 * 1000;  // 250ms

        if (IsWow64) {
            // 32位进程
            PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(Process);
            if (!peb32) {
                return NULL;
            }

            // 等待Ldr初始化
            for (INT i = 0; !peb32->Ldr && i < 10; i++) {
                KeDelayExecutionThread(KernelMode, TRUE, &waitTime);
            }

            if (!peb32->Ldr) {
                return NULL;
            }

            PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)(ULONG_PTR)peb32->Ldr;

            for (PLIST_ENTRY32 entry = (PLIST_ENTRY32)ldr->InLoadOrderModuleList.Flink;
                entry != &ldr->InLoadOrderModuleList;
                entry = (PLIST_ENTRY32)entry->Flink) {

                PLDR_DATA_TABLE_ENTRY32 ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

                UNICODE_STRING entryName;
                entryName.Length = ldrEntry->BaseDllName.Length;
                entryName.MaximumLength = ldrEntry->BaseDllName.MaximumLength;
                entryName.Buffer = (PWCH)(ULONG_PTR)ldrEntry->BaseDllName.Buffer;

                if (RtlCompareUnicodeString(&entryName, ModuleName, TRUE) == 0) {
                    return (PVOID)(ULONG_PTR)ldrEntry->DllBase;
                }
            }
        }
        else {
            // 64位进程
            PPEB peb = PsGetProcessPeb(Process);
            if (!peb) {
                return NULL;
            }

            // 等待Ldr初始化
            for (INT i = 0; !peb->Ldr && i < 10; i++) {
                KeDelayExecutionThread(KernelMode, TRUE, &waitTime);
            }

            if (!peb->Ldr) {
                return NULL;
            }

            for (PLIST_ENTRY entry = peb->Ldr->InLoadOrderModuleList.Flink;
                entry != &peb->Ldr->InLoadOrderModuleList;
                entry = entry->Flink) {

                PHIDE_LDR_ENTRY ldrEntry = CONTAINING_RECORD(entry, HIDE_LDR_ENTRY, InLoadOrderLinks);

                if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, ModuleName, TRUE) == 0) {
                    return ldrEntry->DllBase;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_GetUserModuleBase: Exception occurred\n");
    }

    return NULL;
}

//
// Utils_GetModuleExportAddress
//
PVOID Utils_GetModuleExportAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
)
{
    KAPC_STATE apcState;
    PVOID functionAddress = NULL;

    // 1. 附加进程
    if (Process != NULL) {
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
    }

    do
    {
        if (!ModuleBase || !FunctionName) {
            break;
        }

        // 2. 解析头部：支持 PE32 和 PE32+（WoW64 模块为 PE32）
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            break;
        }

        // FileHeader 在 PE32/PE32+ 中偏移相同（Signature 之后）
        PIMAGE_FILE_HEADER fileHdr = (PIMAGE_FILE_HEADER)((ULONG64)ModuleBase + dosHeader->e_lfanew + sizeof(ULONG));
        BOOLEAN isPE32 = (fileHdr->Machine == IMAGE_FILE_MACHINE_I386);

        IMAGE_DATA_DIRECTORY exportDataDir;
        if (isPE32) {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)((ULONG64)ModuleBase + dosHeader->e_lfanew);
            if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE) break;
            exportDataDir = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)((ULONG64)ModuleBase + dosHeader->e_lfanew);
            if (ntHeaders64->Signature != IMAGE_NT_SIGNATURE) break;
            exportDataDir = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }

        if (exportDataDir.Size == 0 || exportDataDir.VirtualAddress == 0) {
            break;
        }

        PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + exportDataDir.VirtualAddress);

        // 获取导出表数组地址
        PULONG addressOfFunctions = (PULONG)((ULONG64)ModuleBase + exportDirectory->AddressOfFunctions);
        PULONG addressOfNames = (PULONG)((ULONG64)ModuleBase + exportDirectory->AddressOfNames);
        PUSHORT addressOfOrdinals = (PUSHORT)((ULONG64)ModuleBase + exportDirectory->AddressOfNameOrdinals);

        // 3. 使用 RtlInitString 和 RtlCompareString 比较字符串
        STRING targetFunctionName;
        RtlInitString(&targetFunctionName, FunctionName);

        // 按 NumberOfNames 遍历导出名称数组
        for (ULONG i = 0; i < exportDirectory->NumberOfNames; i++)
        {
            STRING currentFunctionName;
            RtlInitString(&currentFunctionName, (PCHAR)ModuleBase + addressOfNames[i]);

            // TRUE 表示不区分大小写，与参考代码一致
            if (RtlCompareString(&targetFunctionName, &currentFunctionName, TRUE) == 0)
            {
                // 获取序号，检查是否为转发导出（Windows 10: KERNEL32 大量函数转发到 KERNELBASE）
                USHORT ordinal  = addressOfOrdinals[i];
                ULONG  funcRva  = addressOfFunctions[ordinal];

                // 转发导出：RVA 落在导出目录范围内，值为转发字符串（如 "KERNELBASE.VirtualAlloc"）
                if (funcRva >= exportDataDir.VirtualAddress &&
                    funcRva <  exportDataDir.VirtualAddress + exportDataDir.Size)
                {
                    if (Process) {
                        // 格式："ModuleName.FunctionName"（模块名不带 .dll 后缀）
                        PCSTR fwdStr = (PCSTR)((ULONG64)ModuleBase + funcRva);
                        CHAR  fwdMod[72] = { 0 };
                        PCSTR dotPos = NULL;
                        for (int fj = 0; fj < 63 && fwdStr[fj]; fj++) {
                            if (fwdStr[fj] == '.') { dotPos = fwdStr + fj; break; }
                            fwdMod[fj] = fwdStr[fj];
                        }
                        if (dotPos) {
                            ULONG_PTR modLen = (ULONG_PTR)(dotPos - fwdStr);
                            if (modLen + 4 < sizeof(fwdMod)) {
                                fwdMod[modLen]   = '.';
                                fwdMod[modLen+1] = 'd';
                                fwdMod[modLen+2] = 'l';
                                fwdMod[modLen+3] = 'l';
                            }
                            PCSTR fwdFunc = dotPos + 1;
                            WCHAR wFwdMod[72] = { 0 };
                            for (ULONG_PTR fj = 0; fj < 71 && fwdMod[fj]; fj++)
                                wFwdMod[fj] = (WCHAR)(UCHAR)fwdMod[fj];
                            UNICODE_STRING fwdUni;
                            RtlInitUnicodeString(&fwdUni, wFwdMod);
                            // Utils_GetUserModuleBase / Utils_GetModuleExportAddress
                            // 内部会处理 KeStackAttachProcess 嵌套，此处直接调用
                            // 使用当前模块的 PE 类型推断 IsWow64（PE32 模块 → WoW64 进程）
                            PVOID fwdBase = Utils_GetUserModuleBase(Process, &fwdUni, isPE32);
                            if (fwdBase)
                                functionAddress = Utils_GetModuleExportAddress(Process, fwdBase, fwdFunc);
                        }
                    }
                    // Process == NULL（SSDT 路径）时跳过转发解析，保持 functionAddress = NULL
                } else {
                    functionAddress = (PVOID)((ULONG64)ModuleBase + funcRva);
                }
                break;
            }
        }

    } while (0);

    // 4. 解除附加
    if (Process != NULL) {
        KeUnstackDetachProcess(&apcState);
    }

    return functionAddress;
}

PVOID Utils_GetNtdllExportAddress(
    _In_ PEPROCESS Process,
    _In_ PCSTR FunctionName,
    _In_ BOOLEAN IsWow64
)
{
    UNICODE_STRING ntdllName;
    RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    PVOID ntdllBase = Utils_GetUserModuleBase(Process, &ntdllName, IsWow64);
    PVOID funcAddr = NULL;

    if (ntdllBase) {
        funcAddr = Utils_GetModuleExportAddress(NULL, ntdllBase, FunctionName);
    }

    KeUnstackDetachProcess(&apcState);

    DBG_PRINT("Utils_GetNtdllExportAddress: %s = %p (ntdll base = %p)\n",
        FunctionName, funcAddr, ntdllBase);

    return funcAddr;
}

// ============================================================================
// SSDT工具实现
// ============================================================================

NTSTATUS Utils_InitializeSSDT(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }

    // 1. 遍历 LDR 获取 ntoskrnl 基址
    UNICODE_STRING osName;
    RtlInitUnicodeString(&osName, L"ntoskrnl.exe");

    PLDR_DATA_TABLE_ENTRY dataTableEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!dataTableEntry) {
        DBG_PRINT("Utils_InitializeSSDT: DriverSection is NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    PVOID ntosBase = NULL;

    for (PLIST_ENTRY entry = dataTableEntry->InLoadOrderLinks.Flink;
        entry != &dataTableEntry->InLoadOrderLinks;
        entry = entry->Flink) {

        PHIDE_LDR_ENTRY moduleEntry = CONTAINING_RECORD(entry, HIDE_LDR_ENTRY, InLoadOrderLinks);

        if (RtlCompareUnicodeString(&moduleEntry->BaseDllName, &osName, TRUE) == 0) {
            ntosBase = moduleEntry->DllBase;
            break;
        }
    }

    if (!ntosBase) {
        DBG_PRINT("Utils_InitializeSSDT: Failed to find ntoskrnl.exe\n");
        return STATUS_NOT_FOUND;
    }

    DBG_PRINT("Utils_InitializeSSDT: ntoskrnl.exe base = %p\n", ntosBase);

    // 2. 以 _stricmp 导出地址作为扫描起点
    PVOID scanStartAddr = Utils_GetModuleExportAddress(NULL, ntosBase, "_stricmp");

    if (!scanStartAddr) {
        DBG_PRINT("Utils_InitializeSSDT: Failed to find _stricmp export\n");
        // 找不到 _stricmp 时，从模块基址开始扫描
        scanStartAddr = ntosBase;
    }

    DBG_PRINT("Utils_InitializeSSDT: Scan start address (_stricmp) = %p\n", scanStartAddr);

    // 3. 定义特征码
    // mov edi,eax; shr edi,7; and edi,20h; and eax,0FFFh
    UCHAR pattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

    // 4. 执行扫描 (参考实现逻辑)
    // 范围：0x50000 (约320KB)
    ULONG64 scanSize = 0x50000;
    PUCHAR codeScanStart = (PUCHAR)scanStartAddr;
    BOOLEAN found = FALSE;

    for (ULONG64 i = 0; i < scanSize; i++)
    {
        // 比较特征码
        if (RtlCompareMemory(codeScanStart + i, pattern, sizeof(pattern)) == sizeof(pattern))
        {
            // 参考实现：找到特征码后，向后搜索 50 字节寻找 LEA 指令
            PUCHAR matchAddr = codeScanStart + i;

            for (ULONG b = 0; b < 50; b++)
            {
                PUCHAR targetAddr = matchAddr + b;

                // 检查指令: 4C 8D (lea r10/r11/...)
                // 参考代码: if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
                // 0x8d4c 是 4C 8D 的小端序表示
                if (*(PUSHORT)targetAddr == 0x8D4C)
                {
                    // 找到了: lea r10, [KeServiceDescriptorTable]
                    // 指令格式: 4C 8D 15 [Offset 4 Bytes]

                    LONG offset = *(PLONG)(targetAddr + 3);

                    // 计算绝对地址: 当前指令地址 + 指令长度(7) + 偏移
                    g_KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)(targetAddr + 7 + offset);

                    DBG_PRINT("Utils_InitializeSSDT: Pattern found at %p\n", matchAddr);
                    DBG_PRINT("Utils_InitializeSSDT: KeServiceDescriptorTable = %p\n", g_KeServiceDescriptorTable);

                    found = TRUE;
                    break;
                }
            }
        }

        if (found) break;
    }

    if (!found) {
        DBG_PRINT("Utils_InitializeSSDT: Failed to locate SSDT via pattern scan\n");
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

//
// Utils_GetSSDTIndex
//
ULONG Utils_GetSSDTIndex(
    _In_ PCSTR FunctionName
)
{
    NTSTATUS status;
    HANDLE sectionHandle = NULL;
    PVOID ntdllBase = NULL;
    SIZE_T viewSize = 0;
    ULONG syscallIndex = (ULONG)-1;
    UNICODE_STRING sectionName;
    OBJECT_ATTRIBUTES objAttr;

    // 初始化路径 \KnownDlls\ntdll.dll
    RtlInitUnicodeString(&sectionName, L"\\KnownDlls\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenSection(&sectionHandle, SECTION_MAP_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Utils_GetSSDTIndex: ZwOpenSection failed (0x%08X)\n", status);
        return (ULONG)-1;
    }

    status = ZwMapViewOfSection(
        sectionHandle,
        ZwCurrentProcess(),
        &ntdllBase,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Utils_GetSSDTIndex: ZwMapViewOfSection failed (0x%08X)\n", status);
        ZwClose(sectionHandle);
        return (ULONG)-1;
    }

    do {
        // 传入 NULL 作为 Process，因为 ntdllBase 已经映射在当前进程空间
        PVOID funcAddress = Utils_GetModuleExportAddress(NULL, ntdllBase, FunctionName);

        // 如果找不到且是 Zw 开头，尝试找 Nt 开头
        if (!funcAddress && FunctionName[0] == 'Z' && FunctionName[1] == 'w') {
            CHAR ntName[64];
            strcpy(ntName, FunctionName);
            ntName[0] = 'N';
            ntName[1] = 't';
            funcAddress = Utils_GetModuleExportAddress(NULL, ntdllBase, ntName);
        }

        if (funcAddress) {
            // 读取地址 + 4 处的 4 字节整数 (mov eax, index)
            syscallIndex = *(PULONG)((PUCHAR)funcAddress + 4);
        }
        else {
            DBG_PRINT("Utils_GetSSDTIndex: Function %s not found in ntdll export\n", FunctionName);
        }

    } while (0);

    ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);
    ZwClose(sectionHandle);

    return syscallIndex;
}

//
// Utils_GetSSDTFunctionAddress
//
PVOID Utils_GetSSDTFunctionAddress(
    _In_ ULONG Index
)
{
    if (!g_KeServiceDescriptorTable || !g_KeServiceDescriptorTable->ServiceTableBase) {
        DBG_PRINT("Utils_GetSSDTFunctionAddress: SSDT not initialized\n");
        return NULL;
    }

    if (Index >= g_KeServiceDescriptorTable->NumberOfServices) {
        DBG_PRINT("Utils_GetSSDTFunctionAddress: Index %lu out of range\n", Index);
        return NULL;
    }

    PULONG serviceTable = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;

    // 核心计算逻辑：Base + (Table[Index] >> 4)
    LONG offset = serviceTable[Index] >> 4;
    PVOID funcAddr = (PVOID)((PUCHAR)serviceTable + offset);

    return funcAddr;
}

// ============================================================================
// 系统调用号工具实现
// ============================================================================

USHORT Utils_GetSyscallNumber(
    _In_ PCSTR NtFunctionName
)
{
    ULONG index = Utils_GetSSDTIndex(NtFunctionName);

    if (index == (ULONG)-1) {
        return 0;
    }

    return (USHORT)index;
}

// ============================================================================
// 驱动签名绕过实现
// ============================================================================

BOOLEAN Utils_BypassCheckSign(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    if (!DriverObject) {
        return FALSE;
    }

#ifdef _WIN64
    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY listEntry;
        ULONG64 __Undefined1;
        ULONG64 __Undefined2;
        ULONG64 __Undefined3;
        ULONG64 NonPagedDebugInfo;
        ULONG64 DllBase;
        ULONG64 EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG   Flags;
        USHORT  LoadCount;
        USHORT  __Undefined5;
        ULONG64 __Undefined6;
        ULONG   CheckSum;
        ULONG   __padding1;
        ULONG   TimeDateStamp;
        ULONG   __padding2;
    } KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY listEntry;
        ULONG unknown1;
        ULONG unknown2;
        ULONG unknown3;
        ULONG unknown4;
        ULONG unknown5;
        ULONG unknown6;
        ULONG unknown7;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG   Flags;
    } KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

    PKLDR_DATA_TABLE_ENTRY ldrData = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    if (ldrData) {
        ldrData->Flags |= 0x20;
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// 调试工具实现
// ============================================================================

VOID Utils_HexDump(
    _In_ PVOID Address,
    _In_ SIZE_T Length,
    _In_opt_ PCSTR Label
)
{
    if (!Address || Length == 0) {
        return;
    }

    PUCHAR bytes = (PUCHAR)Address;

    if (Label) {
        DBG_PRINT("=== %s (%p, %zu bytes) ===\n", Label, Address, Length);
    }

    for (SIZE_T i = 0; i < Length; i += 16) {
        CHAR hexBuf[64] = { 0 };
        CHAR ascBuf[20] = { 0 };

        for (SIZE_T j = 0; j < 16 && (i + j) < Length; j++) {
            UCHAR b = bytes[i + j];

            // Hex部分
            CHAR hexPart[4];
            RtlStringCbPrintfA(hexPart, sizeof(hexPart), "%02X ", b);
            RtlStringCbCatA(hexBuf, sizeof(hexBuf), hexPart);

            // ASCII部分
            ascBuf[j] = (b >= 0x20 && b < 0x7F) ? b : '.';
        }

        DBG_PRINT("%04zX: %-48s  %s\n", i, hexBuf, ascBuf);
    }
}


// ============================================================================
// Utils_HideModuleInProcess - 进程内模块隐藏
// ============================================================================

// ---- L1: 从 PEB64 加载器链表移除模块 ----
static VOID HideModule_L1_UnlinkPeb64(
    _In_ PEPROCESS  Process,
    _In_ ULONG_PTR  ModuleBase,
    _In_ KAPC_STATE* ApcState
)
{
    __try {
        PPEB       peb = PsGetProcessPeb(Process);
        if (!peb || !peb->Ldr) return;

        PPEB_LDR_DATA ldr = peb->Ldr;

        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY cur  = head->Flink;

        while (cur && cur != head) {
            PHIDE_LDR_ENTRY entry = CONTAINING_RECORD(
                cur, HIDE_LDR_ENTRY, InLoadOrderLinks);
            cur = cur->Flink;

            if ((ULONG_PTR)entry->DllBase == ModuleBase) {
                RemoveEntryList(&entry->InLoadOrderLinks);
                RemoveEntryList(&entry->InMemoryOrderLinks);
                RemoveEntryList(&entry->InInitializationOrderLinks);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
                DBG_PRINT("Utils_HideModuleInProcess: L1 unlinked 64-bit PEB Ldr for %p\n",
                    (PVOID)ModuleBase);
#endif
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_HideModuleInProcess: L1 exception (0x%08X)\n", GetExceptionCode());
    }
}

// ---- L2: 清零 PE 头 ----
static VOID HideModule_L2_EraseHeaders(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR ModuleBase
)
{
    __try {
        // 从 PE OptionalHeader 读取 SizeOfHeaders（精确擦除，避免越界）
        PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)ModuleBase;
        PIMAGE_NT_HEADERS ntHdr  = (PIMAGE_NT_HEADERS)(ModuleBase + dosHdr->e_lfanew);
        SIZE_T hdrSize = ntHdr->OptionalHeader.SizeOfHeaders;
        if (hdrSize == 0 || hdrSize > 0x2000) hdrSize = 0x1000;  // 安全回退

        PVOID  base    = (PVOID)ModuleBase;
        ULONG  oldProt = 0;

        NTSTATUS st = ZwProtectVirtualMemory(
            NtCurrentProcess(), &base, &hdrSize, PAGE_EXECUTE_READWRITE, &oldProt);

        if (NT_SUCCESS(st)) {
            RtlZeroMemory((PVOID)ModuleBase, hdrSize);

            ZwProtectVirtualMemory(
                NtCurrentProcess(), &base, &hdrSize, oldProt, &oldProt);

#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE
            DBG_PRINT("Utils_HideModuleInProcess: L2 erased PE headers at %p\n",
                (PVOID)ModuleBase);
#endif
        } else {
            DBG_PRINT("Utils_HideModuleInProcess: L2 VirtualProtect failed (0x%08X)\n", st);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_HideModuleInProcess: L2 exception (0x%08X)\n", GetExceptionCode());
    }
}

// ---- L3: 查询内存信息；VAD 隐藏尚未实现 ----
static VOID HideModule_L3_FakeVad(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR ModuleBase,
    _In_ SIZE_T    ModuleSize
)
{
    __try {

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T retlen = 0;
        NTSTATUS st = ZwQueryVirtualMemory(
            NtCurrentProcess(),
            (PVOID)ModuleBase,
            (MEMORY_INFORMATION_CLASS)0, // MemoryBasicInformation
            &mbi, sizeof(mbi), &retlen);

        if (NT_SUCCESS(st)) {
            DBG_PRINT("Utils_HideModuleInProcess: L3 VAD check: Type=%lu State=%lu\n",
                mbi.Type, mbi.State);
        }

        PVOID vadRoot = (PVOID)((ULONG_PTR)Process +
            (ULONG_PTR)0x7D8);

        DBG_PRINT("Utils_HideModuleInProcess: L3 VAD hiding not fully implemented (pending)\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_HideModuleInProcess: L3 exception (0x%08X)\n", GetExceptionCode());
    }
}

// ---- L4: 从 WoW64 PEB32 加载器链表移除模块 ----
static VOID HideModule_L4_UnlinkPeb32(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR ModuleBase
)
{
    __try {
        PVOID peb32Ptr = PsGetProcessWow64Process(Process);
        if (!peb32Ptr) return;

        PPEB32 peb32 = (PPEB32)peb32Ptr;
        if (!peb32->Ldr) return;

        PPEB_LDR_DATA32 ldr32 = (PPEB_LDR_DATA32)(ULONG_PTR)peb32->Ldr;

        PLIST_ENTRY32 head32 = &ldr32->InLoadOrderModuleList;
        PLIST_ENTRY32 cur32  = (PLIST_ENTRY32)(ULONG_PTR)head32->Flink;

        while (cur32 && cur32 != head32) {
            PLDR_DATA_TABLE_ENTRY32 entry32 = CONTAINING_RECORD(
                cur32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
            cur32 = (PLIST_ENTRY32)(ULONG_PTR)cur32->Flink;

            if ((ULONG_PTR)entry32->DllBase == ModuleBase) {
                PLIST_ENTRY32 flink, blink;

                flink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InLoadOrderLinks.Flink;
                blink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InLoadOrderLinks.Blink;
                if (flink) flink->Blink = entry32->InLoadOrderLinks.Blink;
                if (blink) blink->Flink = entry32->InLoadOrderLinks.Flink;

                flink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InMemoryOrderLinks.Flink;
                blink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InMemoryOrderLinks.Blink;
                if (flink) flink->Blink = entry32->InMemoryOrderLinks.Blink;
                if (blink) blink->Flink = entry32->InMemoryOrderLinks.Flink;

                flink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InInitializationOrderLinks.Flink;
                blink = (PLIST_ENTRY32)(ULONG_PTR)entry32->InInitializationOrderLinks.Blink;
                if (flink) flink->Blink = entry32->InInitializationOrderLinks.Blink;
                if (blink) blink->Flink = entry32->InInitializationOrderLinks.Flink;

                DBG_PRINT("Utils_HideModuleInProcess: L4 unlinked 32-bit PEB Ldr for %p\n",
                    (PVOID)ModuleBase);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_HideModuleInProcess: L4 exception (0x%08X)\n", GetExceptionCode());
    }
}

// ---- 模块隐藏入口 ----
NTSTATUS Utils_HideModuleInProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR ModuleBase,
    _In_ SIZE_T    ModuleSize,
    _In_ BOOLEAN   IsWow64
)
{
    if (!Process || !ModuleBase) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try {
        // L1: 从 PEB64 加载器链表移除模块
        HideModule_L1_UnlinkPeb64(Process, ModuleBase, &apcState);

        // L2: 清零 PE 头
        HideModule_L2_EraseHeaders(Process, ModuleBase);

        // L3: 查询内存信息
        HideModule_L3_FakeVad(Process, ModuleBase, ModuleSize);

        // L4: 处理 WoW64 PEB32 加载器链表
        if (IsWow64) {
            HideModule_L4_UnlinkPeb32(Process, ModuleBase);
        }

        DBG_PRINT("Utils_HideModuleInProcess: Completed L1-L%d hiding for %p\n",
            IsWow64 ? 4 : 3, (PVOID)ModuleBase);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Utils_HideModuleInProcess: Outer exception (0x%08X)\n", GetExceptionCode());
    }

    KeUnstackDetachProcess(&apcState);

    return STATUS_SUCCESS;
}
