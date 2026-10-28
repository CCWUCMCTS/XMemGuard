// ============================================================================
// DataManager.cpp - 核心数据结构管理实现
// ============================================================================

#include "DataManager.hpp"

// ============================================================================
// 全局实例
// ============================================================================
DATA_MANAGER g_DataManager = { 0 };

// ============================================================================
// 内部辅助函数声明
// ============================================================================

// Hash计算
static __forceinline ULONG HashProcessId(HANDLE ProcessId)
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    // 简单的乘法Hash
    pid = pid * 2654435761UL;
    return (ULONG)(pid % PROCESS_HASH_TABLE_SIZE);
}

// AVL树比较函数
static RTL_GENERIC_COMPARE_RESULTS NTAPI
MemoryRegionCompare(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
);

// AVL树分配函数
static PVOID NTAPI
MemoryRegionAllocate(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize
);

// AVL树释放函数
static VOID NTAPI
MemoryRegionFree(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
);

static BOOLEAN TryCalculateRegionEnd(
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T Size,
    _Out_ PULONG_PTR EndAddress
)
{
    if (!EndAddress || Size == 0) {
        return FALSE;
    }

    if (BaseAddress > MAXULONG_PTR - Size) {
        return FALSE;
    }

    *EndAddress = BaseAddress + Size;
    return TRUE;
}

static VOID DataManager_RetireProcessNode(
    _In_ PPROCESS_NODE Node
);

// ============================================================================
// 初始化与清理
// ============================================================================

NTSTATUS DataManager_Initialize(VOID)
{
    DBG_PRINT("DataManager_Initialize: Starting initialization\n");

    if (g_DataManager.IsInitialized) {
        DBG_PRINT("DataManager_Initialize: Already initialized\n");
        return STATUS_SUCCESS;
    }

    // 初始化Hash表
    for (ULONG i = 0; i < PROCESS_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&g_DataManager.ProcessTable[i].ListHead);
        ExInitializePushLock(&g_DataManager.ProcessTable[i].BucketLock);
    }

    // 初始化日志环形缓冲区
    g_DataManager.LogCapacity = 1024;
    g_DataManager.LogBuffer = (PSHELLCODE_LOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SHELLCODE_LOG_ENTRY) * g_DataManager.LogCapacity,
        POOL_TAG_COMMON
    );

    if (!g_DataManager.LogBuffer) {
        DBG_PRINT("DataManager_Initialize: Failed to allocate log buffer\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DataManager.LogBuffer,
        sizeof(SHELLCODE_LOG_ENTRY) * g_DataManager.LogCapacity);

    g_DataManager.LogHead = 0;
    g_DataManager.LogTail = 0;
    KeInitializeSpinLock(&g_DataManager.LogLock);

    // 初始化统计
    g_DataManager.TotalProcessCount = 0;
    g_DataManager.TotalRegionCount = 0;

    g_DataManager.IsInitialized = TRUE;

    DBG_PRINT("DataManager_Initialize: Initialization complete\n");
    return STATUS_SUCCESS;
}

VOID DataManager_Cleanup(VOID)
{
    DBG_PRINT("DataManager_Cleanup: Starting cleanup\n");

    if (!g_DataManager.IsInitialized) {
        return;
    }

    // 遍历所有HashBucket，释放所有进程节点
    for (ULONG i = 0; i < PROCESS_HASH_TABLE_SIZE; i++) {
        PHASH_BUCKET bucket = &g_DataManager.ProcessTable[i];

        ExAcquirePushLockExclusive(&bucket->BucketLock);

        while (!IsListEmpty(&bucket->ListHead)) {
            PLIST_ENTRY entry = RemoveHeadList(&bucket->ListHead);
            PPROCESS_NODE processNode = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);

            DBG_PRINT("DataManager_Cleanup: Freeing process node for PID %lu\n",
                (ULONG)(ULONG_PTR)processNode->ProcessId);

            // 释放AVL树中的所有内存区域
            PVOID restartKey = NULL;
            PMEMORY_REGION_NODE regionNode;

            while ((regionNode = (PMEMORY_REGION_NODE)RtlEnumerateGenericTableAvl(
                &processNode->MemoryRegionTable, TRUE)) != NULL) {
                RtlDeleteElementGenericTableAvl(&processNode->MemoryRegionTable, regionNode);
            }

            // 释放进程节点
            ExFreePoolWithTag(processNode, POOL_TAG_PROCESS);
        }

        ExReleasePushLockExclusive(&bucket->BucketLock);
    }

    // 释放日志缓冲区
    if (g_DataManager.LogBuffer) {
        ExFreePoolWithTag(g_DataManager.LogBuffer, POOL_TAG_COMMON);
        g_DataManager.LogBuffer = NULL;
    }

    g_DataManager.IsInitialized = FALSE;

    DBG_PRINT("DataManager_Cleanup: Cleanup complete\n");
}

// ============================================================================
// AVL树回调实现
// ============================================================================

static RTL_GENERIC_COMPARE_RESULTS NTAPI
MemoryRegionCompare(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
)
{
    UNREFERENCED_PARAMETER(Table);

    PMEMORY_REGION_NODE first = (PMEMORY_REGION_NODE)FirstStruct;
    PMEMORY_REGION_NODE second = (PMEMORY_REGION_NODE)SecondStruct;

    // 区间比较，检测是否重叠
    // [first.Start, first.End) vs [second.Start, second.End)

    if (first->EndAddress <= second->StartAddress) {
        return GenericLessThan;
    }
    else if (first->StartAddress >= second->EndAddress) {
        return GenericGreaterThan;
    }
    else {
        // 区间重叠，视为相等
        return GenericEqual;
    }
}

static PVOID NTAPI
MemoryRegionAllocate(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize
)
{
    UNREFERENCED_PARAMETER(Table);

    PVOID buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        ByteSize,
        POOL_TAG_MEMORY
    );

    if (buffer) {
        RtlZeroMemory(buffer, ByteSize);
    }

    return buffer;
}

static VOID NTAPI
MemoryRegionFree(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
)
{
    UNREFERENCED_PARAMETER(Table);

    if (Buffer) {
        ExFreePoolWithTag(Buffer, POOL_TAG_MEMORY);
    }
}

// ============================================================================
// 进程管理实现
// ============================================================================

PPROCESS_NODE DataManager_FindOrCreateProcess(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_opt_ PBOOLEAN WasCreated
)
{
    if (!g_DataManager.IsInitialized) {
        DBG_PRINT("DataManager_FindOrCreateProcess: Not initialized\n");
        return NULL;
    }

    if (WasCreated) {
        *WasCreated = FALSE;
    }

    ULONG bucketIndex = HashProcessId(ProcessId);
    PHASH_BUCKET bucket = &g_DataManager.ProcessTable[bucketIndex];

    // 首先尝试只读查找
    ExAcquirePushLockShared(&bucket->BucketLock);

    PLIST_ENTRY entry = bucket->ListHead.Flink;
    while (entry != &bucket->ListHead) {
        PPROCESS_NODE node = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);

        if (node->ProcessId == ProcessId) {
            // 检测是否PID重用
            if (node->ProcessCreateTime == CreateTime) {
                // 增加引用计数
                InterlockedIncrement(&node->ReferenceCount);
                ExReleasePushLockShared(&bucket->BucketLock);

                return node;
            }
            // PID重用，需要删除旧节点并创建新节点
            break;
        }
        entry = entry->Flink;
    }

    ExReleasePushLockShared(&bucket->BucketLock);

    // 需要创建新节点，获取排他锁
    ExAcquirePushLockExclusive(&bucket->BucketLock);

    // 双重检查
    entry = bucket->ListHead.Flink;
    PPROCESS_NODE oldNode = NULL;

    while (entry != &bucket->ListHead) {
        PPROCESS_NODE node = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);

        if (node->ProcessId == ProcessId) {
            if (node->ProcessCreateTime == CreateTime) {
                // 另一个线程已创建
                InterlockedIncrement(&node->ReferenceCount);
                ExReleasePushLockExclusive(&bucket->BucketLock);
                return node;
            }
            // 标记旧节点待删除
            oldNode = node;
            break;
        }
        entry = entry->Flink;
    }

    // 若有旧节点（PID重用），先从哈希链表摘除；
    // 释放动作统一走延迟释放模型，避免其他线程仍持有旧节点引用时直接 free。
    if (oldNode) {
        DBG_PRINT("DataManager_FindOrCreateProcess: PID reuse detected for PID %lu\n",
            (ULONG)(ULONG_PTR)ProcessId);

        RemoveEntryList(&oldNode->HashLink);
        InterlockedDecrement(&g_DataManager.TotalProcessCount);
    }

    // 创建新节点
    PPROCESS_NODE newNode = (PPROCESS_NODE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PROCESS_NODE),
        POOL_TAG_PROCESS
    );

    if (!newNode) {
        ExReleasePushLockExclusive(&bucket->BucketLock);
        if (oldNode) {
            DataManager_RetireProcessNode(oldNode);
        }
        DBG_PRINT("DataManager_FindOrCreateProcess: Failed to allocate process node\n");
        return NULL;
    }

    RtlZeroMemory(newNode, sizeof(PROCESS_NODE));

    newNode->ProcessId = ProcessId;
    newNode->ProcessCreateTime = CreateTime;
    newNode->ReferenceCount = 1;  // 初始引用计数
    newNode->IsHookInstalled = FALSE;
    newNode->RegionCount = 0;

    ExInitializePushLock(&newNode->NodeLock);

    // 初始化AVL树
    RtlInitializeGenericTableAvl(
        &newNode->MemoryRegionTable,
        MemoryRegionCompare,
        MemoryRegionAllocate,
        MemoryRegionFree,
        NULL
    );

    // 加入链表
    InsertTailList(&bucket->ListHead, &newNode->HashLink);
    InterlockedIncrement(&g_DataManager.TotalProcessCount);

    ExReleasePushLockExclusive(&bucket->BucketLock);

    if (oldNode) {
        DataManager_RetireProcessNode(oldNode);
    }

    if (WasCreated) {
        *WasCreated = TRUE;
    }

    DBG_PRINT("DataManager_FindOrCreateProcess: Created new node for PID %lu\n",
        (ULONG)(ULONG_PTR)ProcessId);

    return newNode;
}

PPROCESS_NODE DataManager_FindProcess(
    _In_ HANDLE ProcessId
)
{
    if (!g_DataManager.IsInitialized) {
        return NULL;
    }

    ULONG bucketIndex = HashProcessId(ProcessId);
    PHASH_BUCKET bucket = &g_DataManager.ProcessTable[bucketIndex];

    ExAcquirePushLockShared(&bucket->BucketLock);

    PLIST_ENTRY entry = bucket->ListHead.Flink;
    while (entry != &bucket->ListHead) {
        PPROCESS_NODE node = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);

        if (node->ProcessId == ProcessId) {
            InterlockedIncrement(&node->ReferenceCount);
            ExReleasePushLockShared(&bucket->BucketLock);
            return node;
        }
        entry = entry->Flink;
    }

    ExReleasePushLockShared(&bucket->BucketLock);
    return NULL;
}


// ============================================================================
// DataManager_FreeProcessNodeInternal - 释放进程节点（内部辅助）
//
// 功能：清空节点持有的 AVL 树中所有内存区域记录，然后释放节点本身。
//
// 调用前提：调用者已通过 CAS(ReferenceCount: 0 -> -1) 原子认领释放权。
// 此函数不做任何并发保护——认领成功意味着不会有其他线程并发调用本函数，
// 因此不存在双重释放风险。
// ============================================================================
static VOID DataManager_FreeProcessNodeInternal(
    _In_ PPROCESS_NODE Node
)
{
    // 逐一删除 AVL 树中的内存区域节点。
    // RtlEnumerateGenericTableAvl(Restart=TRUE) 始终返回树中第一个元素；
    // 删除后再次调用，直到树为空。
    PMEMORY_REGION_NODE regionNode;
    while ((regionNode = (PMEMORY_REGION_NODE)RtlEnumerateGenericTableAvl(
        &Node->MemoryRegionTable, TRUE)) != NULL)
    {
        RtlDeleteElementGenericTableAvl(&Node->MemoryRegionTable, regionNode);
        InterlockedDecrement(&g_DataManager.TotalRegionCount);
    }

    DBG_PRINT("DataManager_FreeProcessNodeInternal: 已释放 PID %lu 的节点\n",
        (ULONG)(ULONG_PTR)Node->ProcessId);

    ExFreePoolWithTag(Node, POOL_TAG_PROCESS);
}
static VOID DataManager_RetireProcessNode(
    _In_ PPROCESS_NODE Node
)
{
    if (!Node) {
        return;
    }

    Node->PendingRemoval = TRUE;
    KeMemoryBarrier();

    DBG_PRINT("DataManager_RetireProcessNode: PID %lu，当前引用计数 %ld\n",
        (ULONG)(ULONG_PTR)Node->ProcessId, Node->ReferenceCount);

    LONG prev = InterlockedCompareExchange(&Node->ReferenceCount, -1, 0);
    if (prev == 0) {
        DBG_PRINT("DataManager_RetireProcessNode: PID %lu 立即释放\n",
            (ULONG)(ULONG_PTR)Node->ProcessId);
        DataManager_FreeProcessNodeInternal(Node);
    }
    else {
        DBG_PRINT("DataManager_RetireProcessNode: PID %lu 标记延迟释放（当前引用 %ld）\n",
            (ULONG)(ULONG_PTR)Node->ProcessId, prev);
    }
}
VOID DataManager_ReleaseProcess(
    _In_ PPROCESS_NODE ProcessNode
)
{
    if (!ProcessNode) {
        return;
    }

    // 原子递减引用计数。
    // InterlockedDecrement 在 x86/x64 上等价于 LOCK XADD，含完整内存屏障，
    // 保证此后能读到 RemoveProcess 写入的 PendingRemoval 的最新值。
    LONG ref = InterlockedDecrement(&ProcessNode->ReferenceCount);

    // ref < 0 说明 RemoveProcess 已通过 CAS 将 ReferenceCount 设为 -1 并
    // 抢先认领了释放权。节点可能已被释放，不得再访问其任何字段，直接返回。
    if (ref < 0) {
        return;
    }

    // ---- 延迟释放路径 ----
    //
    // 当节点已被标记为"待删除"（PendingRemoval=TRUE）且本次递减使
    // 引用计数恰好降为 0 时，尝试用 CAS(ReferenceCount: 0 -> -1) 认领释放权。
    //
    // 竞态分析：RemoveProcess 也可能并发执行完全相同的 CAS。
    //   - 只有一方能观察到 prev == 0（CAS 成功），由其负责释放节点。
    //   - 另一方观察到 prev != 0（已被置为 -1），跳过释放，防止双重释放。
    if (ref == 0 && ProcessNode->PendingRemoval) {
        LONG prev = InterlockedCompareExchange(&ProcessNode->ReferenceCount, -1, 0);
        if (prev == 0) {
            // CAS 成功：本线程获得释放权，执行延迟释放
            DBG_PRINT("DataManager_ReleaseProcess: PID %lu 延迟释放完成\n",
                (ULONG)(ULONG_PTR)ProcessNode->ProcessId);
            DataManager_FreeProcessNodeInternal(ProcessNode);
        }
        // prev == -1：RemoveProcess 已抢先认领，本线程无需操作
    }
}
VOID DataManager_RemoveProcess(
    _In_ HANDLE ProcessId
)
{
    if (!g_DataManager.IsInitialized) {
        return;
    }

    ULONG bucketIndex = HashProcessId(ProcessId);
    PHASH_BUCKET bucket = &g_DataManager.ProcessTable[bucketIndex];
    PPROCESS_NODE targetNode = NULL;

    // ---- 第一阶段：在桶写锁保护下将节点从哈希链表摘除 ----
    //
    // 节点摘除后，FindProcess / FindOrCreateProcess 在桶锁下搜索链表时
    // 将永远找不到它，因此不会再产生任何新的引用。
    // 仅已持有节点指针（已持有引用计数）的调用者，仍可在之后调用 ReleaseProcess。
    ExAcquirePushLockExclusive(&bucket->BucketLock);

    PLIST_ENTRY entry = bucket->ListHead.Flink;
    while (entry != &bucket->ListHead) {
        PPROCESS_NODE node = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);
        if (node->ProcessId == ProcessId) {
            RemoveEntryList(&node->HashLink);
            InterlockedDecrement(&g_DataManager.TotalProcessCount);
            targetNode = node;
            break;
        }
        entry = entry->Flink;
    }

    ExReleasePushLockExclusive(&bucket->BucketLock);

    if (!targetNode) {
        return;
    }

    // ---- 第二阶段：交给统一的退役逻辑 ----
    //
    // 节点已从哈希链表摘除，不会再产生新引用。
    // DataManager_RetireProcessNode 负责：
    //   1. 设置 PendingRemoval
    //   2. 若当前 RefCount == 0，则立即认领释放权
    //   3. 否则等待最后一个 ReleaseProcess 完成延迟释放
    DataManager_RetireProcessNode(targetNode);
}
VOID DataManager_SetProcessHooked(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ PVOID ShellcodeBase,
    _In_ SIZE_T ShellcodeSize,
    _In_ PVOID TrampolineAddr,
    _In_ HANDLE DeviceHandle
)
{
    if (!ProcessNode) {
        return;
    }

    ExAcquirePushLockExclusive(&ProcessNode->NodeLock);

    ProcessNode->IsHookInstalled = TRUE;
    ProcessNode->ShellcodeBase = ShellcodeBase;
    ProcessNode->ShellcodeSize = ShellcodeSize;
    ProcessNode->TrampolineAddr = TrampolineAddr;
    ProcessNode->DeviceHandle = DeviceHandle;

    ExReleasePushLockExclusive(&ProcessNode->NodeLock);

    DBG_PRINT("DataManager_SetProcessHooked: PID %lu, ShellcodeBase=%p, Size=0x%zx\n",
        (ULONG)(ULONG_PTR)ProcessNode->ProcessId, ShellcodeBase, ShellcodeSize);
}

// ============================================================================
// 内存区域管理实现
// ============================================================================

NTSTATUS DataManager_AddMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG CurrentProtection,
    _In_ ULONG OriginalProtection,
    _In_ HANDLE InitiatorPid
)
{
    if (!ProcessNode || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR endAddress = 0;
    if (!TryCalculateRegionEnd(BaseAddress, Size, &endAddress)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    ExAcquirePushLockExclusive(&ProcessNode->NodeLock);

    // 检查区域数量上限
    if (ProcessNode->RegionCount >= MAX_MEMORY_REGIONS_PER_PROCESS) {
        ExReleasePushLockExclusive(&ProcessNode->NodeLock);
        DBG_PRINT("DataManager_AddMemoryRegion: Max regions reached for PID %lu\n",
            (ULONG)(ULONG_PTR)ProcessNode->ProcessId);
        return STATUS_QUOTA_EXCEEDED;
    }

    // 构建查找节点
    MEMORY_REGION_NODE searchNode = { 0 };
    searchNode.StartAddress = BaseAddress;
    searchNode.EndAddress = endAddress;

    // 检测是否已存在重叠区域
    PMEMORY_REGION_NODE existingNode = (PMEMORY_REGION_NODE)RtlLookupElementGenericTableAvl(
        &ProcessNode->MemoryRegionTable,
        &searchNode
    );

    if (existingNode) {
        // 扩展现有区域
        if (existingNode->EndAddress < searchNode.EndAddress) {
            existingNode->EndAddress = searchNode.EndAddress;
        }
        existingNode->OriginalProtection = OriginalProtection;

        ExReleasePushLockExclusive(&ProcessNode->NodeLock);

        DBG_PRINT("DataManager_AddMemoryRegion: Updated existing region [%p-%p) for PID %lu\n",
            (PVOID)existingNode->StartAddress, (PVOID)existingNode->EndAddress,
            (ULONG)(ULONG_PTR)ProcessNode->ProcessId);
        return STATUS_SUCCESS;
    }

    // 插入新区域
    searchNode.CurrentProtection = CurrentProtection;
    searchNode.OriginalProtection = OriginalProtection;
    searchNode.InitiatorPid = InitiatorPid;
    searchNode.IsDirty = FALSE;
    KeQuerySystemTime(&searchNode.CreateTime);

    // 插入AVL树
    BOOLEAN newElement = FALSE;
    PMEMORY_REGION_NODE insertedNode = (PMEMORY_REGION_NODE)RtlInsertElementGenericTableAvl(
        &ProcessNode->MemoryRegionTable,
        &searchNode,
        sizeof(MEMORY_REGION_NODE),
        &newElement
    );

    if (!insertedNode) {
        ExReleasePushLockExclusive(&ProcessNode->NodeLock);
        DBG_PRINT("DataManager_AddMemoryRegion: Failed to insert region for PID %lu\n",
            (ULONG)(ULONG_PTR)ProcessNode->ProcessId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (newElement) {
        ProcessNode->RegionCount++;
        InterlockedIncrement(&g_DataManager.TotalRegionCount);
    }

    ExReleasePushLockExclusive(&ProcessNode->NodeLock);

    DBG_PRINT("DataManager_AddMemoryRegion: Added region [%p-%p) for PID %lu, Protection %s->%s\n",
        (PVOID)BaseAddress, (PVOID)endAddress,
        (ULONG)(ULONG_PTR)ProcessNode->ProcessId,
        ProtectionToString(OriginalProtection),
        ProtectionToString(CurrentProtection));

    return STATUS_SUCCESS;
}

PMEMORY_REGION_NODE DataManager_FindMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address
)
{
    if (!ProcessNode) {
        return NULL;
    }

    ULONG_PTR searchEnd = 0;
    if (!TryCalculateRegionEnd(Address, 1, &searchEnd)) {
        return NULL;
    }

    ExAcquirePushLockShared(&ProcessNode->NodeLock);

    // 构建查找节点
    MEMORY_REGION_NODE searchNode = { 0 };
    searchNode.StartAddress = Address;
    searchNode.EndAddress = searchEnd;  // 单字节范围

    PMEMORY_REGION_NODE foundNode = (PMEMORY_REGION_NODE)RtlLookupElementGenericTableAvl(
        &ProcessNode->MemoryRegionTable,
        &searchNode
    );

    ExReleasePushLockShared(&ProcessNode->NodeLock);

    return foundNode;
}

PMEMORY_REGION_NODE DataManager_FindMemoryRegionByPidAndAddress(
    _In_ HANDLE ProcessId,
    _In_ ULONG_PTR Address,
    _Out_opt_ PPROCESS_NODE* OutProcessNode
)
{
    PPROCESS_NODE processNode = DataManager_FindProcess(ProcessId);

    if (!processNode) {
        if (OutProcessNode) {
            *OutProcessNode = NULL;
        }
        return NULL;
    }

    PMEMORY_REGION_NODE regionNode = DataManager_FindMemoryRegion(processNode, Address);

    if (OutProcessNode) {
        *OutProcessNode = processNode;
    }
    else {
        // 若调用者不需要进程节点，释放引用
        DataManager_ReleaseProcess(processNode);
    }

    return regionNode;
}

BOOLEAN DataManager_QueryMemoryRegionSnapshot(
    _In_ HANDLE ProcessId,
    _In_ ULONG_PTR Address,
    _Out_ PMEMORY_REGION_NODE RegionSnapshot
)
{
    if (!RegionSnapshot) {
        return FALSE;
    }

    ULONG_PTR searchEnd = 0;
    if (!TryCalculateRegionEnd(Address, 1, &searchEnd)) {
        RtlZeroMemory(RegionSnapshot, sizeof(*RegionSnapshot));
        return FALSE;
    }

    PPROCESS_NODE processNode = DataManager_FindProcess(ProcessId);
    if (!processNode) {
        RtlZeroMemory(RegionSnapshot, sizeof(*RegionSnapshot));
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ExAcquirePushLockShared(&processNode->NodeLock);

    MEMORY_REGION_NODE searchNode = { 0 };
    searchNode.StartAddress = Address;
    searchNode.EndAddress = searchEnd;

    PMEMORY_REGION_NODE regionNode = (PMEMORY_REGION_NODE)RtlLookupElementGenericTableAvl(
        &processNode->MemoryRegionTable,
        &searchNode
    );

    if (regionNode) {
        RtlCopyMemory(RegionSnapshot, regionNode, sizeof(*RegionSnapshot));
        found = TRUE;
    } else {
        RtlZeroMemory(RegionSnapshot, sizeof(*RegionSnapshot));
    }

    ExReleasePushLockShared(&processNode->NodeLock);
    DataManager_ReleaseProcess(processNode);
    return found;
}

NTSTATUS DataManager_UpdateMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address,
    _In_opt_ PULONG NewCurrentProtection,
    _In_opt_ PULONG NewOriginalProtection,
    _In_opt_ PBOOLEAN NewIsDirty,
    _In_opt_ PSIZE_T ExtendSize
)
{
    if (!ProcessNode) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR searchEnd = 0;
    if (!TryCalculateRegionEnd(Address, 1, &searchEnd)) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&ProcessNode->NodeLock);

    MEMORY_REGION_NODE searchNode = { 0 };
    searchNode.StartAddress = Address;
    searchNode.EndAddress = searchEnd;

    PMEMORY_REGION_NODE foundNode = (PMEMORY_REGION_NODE)RtlLookupElementGenericTableAvl(
        &ProcessNode->MemoryRegionTable,
        &searchNode
    );

    if (!foundNode) {
        ExReleasePushLockExclusive(&ProcessNode->NodeLock);
        return STATUS_NOT_FOUND;
    }

    if (NewCurrentProtection) {
        foundNode->CurrentProtection = *NewCurrentProtection;
    }

    if (NewOriginalProtection) {
        foundNode->OriginalProtection = *NewOriginalProtection;
    }

    if (NewIsDirty) {
        foundNode->IsDirty = *NewIsDirty;
    }

    if (ExtendSize && *ExtendSize > 0) {
        ULONG_PTR newEnd = 0;
        if (!TryCalculateRegionEnd(Address, *ExtendSize, &newEnd)) {
            ExReleasePushLockExclusive(&ProcessNode->NodeLock);
            return STATUS_INTEGER_OVERFLOW;
        }
        if (newEnd > foundNode->EndAddress) {
            foundNode->EndAddress = newEnd;
        }
    }

    ExReleasePushLockExclusive(&ProcessNode->NodeLock);

    DBG_PRINT("DataManager_UpdateMemoryRegion: Updated region at %p for PID %lu\n",
        (PVOID)Address, (ULONG)(ULONG_PTR)ProcessNode->ProcessId);

    return STATUS_SUCCESS;
}

NTSTATUS DataManager_RemoveMemoryRegion(
    _In_ PPROCESS_NODE ProcessNode,
    _In_ ULONG_PTR Address
)
{
    if (!ProcessNode) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR searchEnd = 0;
    if (!TryCalculateRegionEnd(Address, 1, &searchEnd)) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&ProcessNode->NodeLock);

    MEMORY_REGION_NODE searchNode = { 0 };
    searchNode.StartAddress = Address;
    searchNode.EndAddress = searchEnd;

    BOOLEAN deleted = RtlDeleteElementGenericTableAvl(
        &ProcessNode->MemoryRegionTable,
        &searchNode
    );

    if (deleted) {
        ProcessNode->RegionCount--;
        InterlockedDecrement(&g_DataManager.TotalRegionCount);
    }

    ExReleasePushLockExclusive(&ProcessNode->NodeLock);

    return deleted ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// 日志管理实现
// ============================================================================

NTSTATUS DataManager_AddLogEntry(
    _In_ PSHELLCODE_LOG_ENTRY Entry
)
{
    if (!g_DataManager.IsInitialized || !Entry) {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DataManager.LogLock, &oldIrql);

    LONG nextTail = (g_DataManager.LogTail + 1) % g_DataManager.LogCapacity;

    // 若缓冲区满，覆盖最旧的条目
    if (nextTail == g_DataManager.LogHead) {
        g_DataManager.LogHead = (g_DataManager.LogHead + 1) % g_DataManager.LogCapacity;
    }

    RtlCopyMemory(&g_DataManager.LogBuffer[g_DataManager.LogTail], Entry, sizeof(SHELLCODE_LOG_ENTRY));
    g_DataManager.LogTail = nextTail;

    KeReleaseSpinLock(&g_DataManager.LogLock, oldIrql);

    DBG_PRINT("DataManager_AddLogEntry: Added log entry for PID %lu, Address %p\n",
        Entry->ProcessId, (PVOID)Entry->FaultAddress);

    return STATUS_SUCCESS;
}

ULONG DataManager_GetLogEntries(
    _Out_writes_(MaxEntries) PSHELLCODE_LOG_ENTRY Buffer,
    _In_ ULONG MaxEntries
)
{
    if (!g_DataManager.IsInitialized || !Buffer || MaxEntries == 0) {
        return 0;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DataManager.LogLock, &oldIrql);

    ULONG count = 0;
    LONG current = g_DataManager.LogHead;

    while (current != g_DataManager.LogTail && count < MaxEntries) {
        RtlCopyMemory(&Buffer[count], &g_DataManager.LogBuffer[current], sizeof(SHELLCODE_LOG_ENTRY));
        current = (current + 1) % g_DataManager.LogCapacity;
        count++;
    }

    // 标记已读取的条目
    g_DataManager.LogHead = current;

    KeReleaseSpinLock(&g_DataManager.LogLock, oldIrql);

    DBG_PRINT("DataManager_GetLogEntries: Retrieved %lu entries\n", count);

    return count;
}

VOID DataManager_ClearLogs(VOID)
{
    if (!g_DataManager.IsInitialized) {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DataManager.LogLock, &oldIrql);

    g_DataManager.LogHead = 0;
    g_DataManager.LogTail = 0;

    KeReleaseSpinLock(&g_DataManager.LogLock, oldIrql);

    DBG_PRINT("DataManager_ClearLogs: Logs cleared\n");
}

// ============================================================================
// 调试和统计实现
// ============================================================================

VOID DataManager_PrintStatistics(VOID)
{
    if (!g_DataManager.IsInitialized) {
        DBG_PRINT("DataManager: Not initialized\n");
        return;
    }

    DBG_PRINT("========== DataManager Statistics ==========\n");
    DBG_PRINT("Total Processes: %ld\n", g_DataManager.TotalProcessCount);
    DBG_PRINT("Total Memory Regions: %ld\n", g_DataManager.TotalRegionCount);
    DBG_PRINT("Log Capacity: %lu\n", g_DataManager.LogCapacity);

    // 计算日志使用量
    LONG logCount;
    if (g_DataManager.LogTail >= g_DataManager.LogHead) {
        logCount = g_DataManager.LogTail - g_DataManager.LogHead;
    }
    else {
        logCount = g_DataManager.LogCapacity - g_DataManager.LogHead + g_DataManager.LogTail;
    }
    DBG_PRINT("Log Entries Used: %ld\n", logCount);
    DBG_PRINT("=============================================\n");
}

VOID DataManager_DumpAllProcesses(VOID)
{
    if (!g_DataManager.IsInitialized) {
        return;
    }

    DBG_PRINT("========== DataManager Process Dump ==========\n");

    for (ULONG i = 0; i < PROCESS_HASH_TABLE_SIZE; i++) {
        PHASH_BUCKET bucket = &g_DataManager.ProcessTable[i];

        ExAcquirePushLockShared(&bucket->BucketLock);

        PLIST_ENTRY entry = bucket->ListHead.Flink;
        while (entry != &bucket->ListHead) {
            PPROCESS_NODE node = CONTAINING_RECORD(entry, PROCESS_NODE, HashLink);

            DBG_PRINT("Bucket[%lu]: PID=%lu, RegionCount=%lu, Hooked=%s, RefCount=%ld\n",
                i,
                (ULONG)(ULONG_PTR)node->ProcessId,
                node->RegionCount,
                node->IsHookInstalled ? "Yes" : "No",
                node->ReferenceCount);

            // 打印内存区域
            ExAcquirePushLockShared(&node->NodeLock);

            PMEMORY_REGION_NODE regionNode;
            for (regionNode = (PMEMORY_REGION_NODE)RtlEnumerateGenericTableAvl(&node->MemoryRegionTable, TRUE);
                regionNode != NULL;
                regionNode = (PMEMORY_REGION_NODE)RtlEnumerateGenericTableAvl(&node->MemoryRegionTable, FALSE)) {

                DBG_PRINT("    Region: [%p - %p), Current=%s, Original=%s, Initiator=%lu\n",
                    (PVOID)regionNode->StartAddress,
                    (PVOID)regionNode->EndAddress,
                    ProtectionToString(regionNode->CurrentProtection),
                    ProtectionToString(regionNode->OriginalProtection),
                    (ULONG)(ULONG_PTR)regionNode->InitiatorPid);
            }

            ExReleasePushLockShared(&node->NodeLock);

            entry = entry->Flink;
        }

        ExReleasePushLockShared(&bucket->BucketLock);
    }

    DBG_PRINT("===============================================\n");
}
