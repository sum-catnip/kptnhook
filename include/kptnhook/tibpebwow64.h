#include <ntifs.h>

// stolen definitions from https://github.com/processhacker/phnt

#define WOW64_POINTER(Type) ULONG

#define GDI_HANDLE_BUFFER_SIZE32 34
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];

#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _GDI_TEB_BATCH32
{
    ULONG Offset;
    WOW64_POINTER(ULONG_PTR) HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH32, *PGDI_TEB_BATCH32;

typedef struct _CLIENT_ID32
{
    ULONG UniqueProcess;
    ULONG UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _TEB32
{
    NT_TIB32 NtTib;

    WOW64_POINTER(PVOID) EnvironmentPointer;
    CLIENT_ID32 ClientId;
    WOW64_POINTER(PVOID) ActiveRpcHandle;
    WOW64_POINTER(PVOID) ThreadLocalStoragePointer;
    WOW64_POINTER(PPEB) ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    WOW64_POINTER(PVOID) CsrClientThread;
    WOW64_POINTER(PVOID) Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    WOW64_POINTER(PVOID) WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    WOW64_POINTER(PVOID) ReservedForDebuggerInstrumentation[16];
    WOW64_POINTER(PVOID) SystemReserved1[36];
    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;

    WOW64_POINTER(PVOID) ActivationContextStackPointer;
    WOW64_POINTER(ULONG_PTR) InstrumentationCallbackSp;
    WOW64_POINTER(ULONG_PTR) InstrumentationCallbackPreviousPc;
    WOW64_POINTER(ULONG_PTR) InstrumentationCallbackPreviousSp;
    BOOLEAN InstrumentationCallbackDisabled;
    UCHAR SpareBytes[23];
    ULONG TxFsContext;

    GDI_TEB_BATCH32 GdiTebBatch;
    CLIENT_ID32 RealClientId;
    WOW64_POINTER(HANDLE) GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    WOW64_POINTER(PVOID) GdiThreadLocalInfo;
    WOW64_POINTER(ULONG_PTR) Win32ClientInfo[62];
    WOW64_POINTER(PVOID) glDispatchTable[233];
    WOW64_POINTER(ULONG_PTR) glReserved1[29];
    WOW64_POINTER(PVOID) glReserved2;
    WOW64_POINTER(PVOID) glSectionInfo;
    WOW64_POINTER(PVOID) glSection;
    WOW64_POINTER(PVOID) glTable;
    WOW64_POINTER(PVOID) glCurrentRC;
    WOW64_POINTER(PVOID) glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING32 StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    WOW64_POINTER(PVOID) DeallocationStack;
    WOW64_POINTER(PVOID) TlsSlots[64];
    LIST_ENTRY32 TlsLinks;

    WOW64_POINTER(PVOID) Vdm;
    WOW64_POINTER(PVOID) ReservedForNtRpc;
    WOW64_POINTER(PVOID) DbgSsReserved[2];

    ULONG HardErrorMode;
    WOW64_POINTER(PVOID) Instrumentation[9];
    GUID ActivityId;

    WOW64_POINTER(PVOID) SubProcessTag;
    WOW64_POINTER(PVOID) PerflibData;
    WOW64_POINTER(PVOID) EtwTraceData;
    WOW64_POINTER(PVOID) WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    WOW64_POINTER(PVOID) ReservedForPerf;
    WOW64_POINTER(PVOID) ReservedForOle;
    ULONG WaitingOnLoaderLock;
    WOW64_POINTER(PVOID) SavedPriorityState;
    WOW64_POINTER(ULONG_PTR) ReservedForCodeCoverage;
    WOW64_POINTER(PVOID) ThreadPoolData;
    WOW64_POINTER(PVOID *) TlsExpansionSlots;

    ULONG MuiGeneration;
    ULONG IsImpersonating;
    WOW64_POINTER(PVOID) NlsCache;
    WOW64_POINTER(PVOID) pShimData;
    USHORT HeapVirtualAffinity;
    USHORT LowFragHeapDataSlot;
    WOW64_POINTER(HANDLE) CurrentTransactionHandle;
    WOW64_POINTER(PTEB_ACTIVE_FRAME) ActiveFrame;
    WOW64_POINTER(PVOID) FlsData;

    WOW64_POINTER(PVOID) PreferredLanguages;
    WOW64_POINTER(PVOID) UserPrefLanguages;
    WOW64_POINTER(PVOID) MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SpareSameTebBits : 2;
        };
    };

    WOW64_POINTER(PVOID) TxnScopeEnterCallback;
    WOW64_POINTER(PVOID) TxnScopeExitCallback;
    WOW64_POINTER(PVOID) TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    WOW64_POINTER(PVOID) ResourceRetValue;
    WOW64_POINTER(PVOID) ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
} TEB32, *PTEB32;

typedef struct _PEB32
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    WOW64_POINTER(HANDLE) Mutant;

    WOW64_POINTER(PVOID) ImageBaseAddress;
    WOW64_POINTER(PPEB_LDR_DATA) Ldr;
    WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
    WOW64_POINTER(PVOID) SubSystemData;
    WOW64_POINTER(PVOID) ProcessHeap;
    WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
    WOW64_POINTER(PVOID) AtlThunkSListPtr;
    WOW64_POINTER(PVOID) IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
    };
    union
    {
        WOW64_POINTER(PVOID) KernelCallbackTable;
        WOW64_POINTER(PVOID) UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    WOW64_POINTER(PVOID) ApiSetMap;
    ULONG TlsExpansionCounter;
    WOW64_POINTER(PVOID) TlsBitmap;
    ULONG TlsBitmapBits[2];
    WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
    WOW64_POINTER(PVOID) HotpatchInformation;
    WOW64_POINTER(PVOID *) ReadOnlyStaticServerData;
    WOW64_POINTER(PVOID) AnsiCodePageData;
    WOW64_POINTER(PVOID) OemCodePageData;
    WOW64_POINTER(PVOID) UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    WOW64_POINTER(SIZE_T) HeapSegmentReserve;
    WOW64_POINTER(SIZE_T) HeapSegmentCommit;
    WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
    WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    WOW64_POINTER(PVOID *) ProcessHeaps;

    WOW64_POINTER(PVOID) GdiSharedHandleTable;
    WOW64_POINTER(PVOID) ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    WOW64_POINTER(ULONG_PTR) ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER32 GdiHandleBuffer;
    WOW64_POINTER(PVOID) PostProcessInitRoutine;

    WOW64_POINTER(PVOID) TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    WOW64_POINTER(PVOID) pShimData;
    WOW64_POINTER(PVOID) AppCompatInfo;

    UNICODE_STRING32 CSDVersion;

    WOW64_POINTER(PVOID) ActivationContextData;
    WOW64_POINTER(PVOID) ProcessAssemblyStorageMap;
    WOW64_POINTER(PVOID) SystemDefaultActivationContextData;
    WOW64_POINTER(PVOID) SystemAssemblyStorageMap;

    WOW64_POINTER(SIZE_T) MinimumStackCommit;

    WOW64_POINTER(PVOID) SparePointers[4];
    ULONG SpareUlongs[5];
    //WOW64_POINTER(PVOID *) FlsCallback;
    //LIST_ENTRY32 FlsListHead;
    //WOW64_POINTER(PVOID) FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    WOW64_POINTER(PVOID) WerRegistrationData;
    WOW64_POINTER(PVOID) WerShipAssertPtr;
    WOW64_POINTER(PVOID) pContextData;
    WOW64_POINTER(PVOID) pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    WOW64_POINTER(PVOID) TppWorkerpListLock;
    LIST_ENTRY32 TppWorkerpList;
    WOW64_POINTER(PVOID) WaitOnAddressHashTable[128];
    WOW64_POINTER(PVOID) TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
} PEB32, *PPEB32;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    BOOLEAN Initialized;
    WOW64_POINTER(HANDLE) SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    WOW64_POINTER(PVOID) EntryInProgress;
    BOOLEAN ShutdownInProgress;
    WOW64_POINTER(HANDLE) ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _RTL_BALANCED_NODE32
{
    union
    {
        WOW64_POINTER(struct _RTL_BALANCED_NODE *) Children[2];
        struct
        {
            WOW64_POINTER(struct _RTL_BALANCED_NODE *) Left;
            WOW64_POINTER(struct _RTL_BALANCED_NODE *) Right;
        };
    };
    union
    {
        WOW64_POINTER(UCHAR) Red : 1;
        WOW64_POINTER(UCHAR) Balance : 2;
        WOW64_POINTER(ULONG_PTR) ParentValue;
    };
} RTL_BALANCED_NODE32, *PRTL_BALANCED_NODE32;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    union
    {
        LIST_ENTRY32 InInitializationOrderLinks;
        LIST_ENTRY32 InProgressLinks;
    };
    WOW64_POINTER(PVOID) DllBase;
    WOW64_POINTER(PVOID) EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
    WOW64_POINTER(struct _ACTIVATION_CONTEXT *) EntryPointActivationContext;
    WOW64_POINTER(PVOID) Lock;
    WOW64_POINTER(PLDR_DDAG_NODE) DdagNode;
    LIST_ENTRY32 NodeModuleLink;
    WOW64_POINTER(struct _LDRP_LOAD_CONTEXT *) LoadContext;
    WOW64_POINTER(PVOID) ParentDllBase;
    WOW64_POINTER(PVOID) SwitchBackContext;
    RTL_BALANCED_NODE32 BaseAddressIndexNode;
    RTL_BALANCED_NODE32 MappingInfoIndexNode;
    WOW64_POINTER(ULONG_PTR) OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;