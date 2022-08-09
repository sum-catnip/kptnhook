#pragma once
#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS RtlSetSaclSecurityDescriptor(
		IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
		IN  BOOLEAN SaclPresent,
		IN  PACL Sacl OPTIONAL,
		IN  BOOLEAN SaclDefaulted OPTIONAL
	);
	NTKERNELAPI const char* PsGetProcessImageFileName(PEPROCESS proc);
	NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
	__declspec(dllimport) NTSTATUS ZwQueryInformationProcess
	(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);
}

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID          Reserved1[2];
	LIST_ENTRY     InMemoryOrderLinks;
	PVOID          Reserved2[2];
	PVOID          DllBase;
	PVOID          EntryPoint;
	PVOID          Reserved3;
	UNICODE_STRING FullDllName;
	UINT8          Reserved4[8];
	PVOID          Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UINT8          Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// https://www.vergiliusproject.com

#ifdef _WIN64
// x64 offsets

#if WINDOWS_REVISION >= 2004
constexpr auto MITIGATION_OFFSET = 0x9d0;
#elif WINDOWS_REVISION >= 1903
constexpr auto MITIGATION_OFFSETT = 0x850;
#elif WINDOWS_REVISION >= 1809
constexpr auto MITIGATION_OFFSETT = 0x820;
#elif WINDOWS_REVISION >= 1709
constexpr auto MITIGATION_OFFSETT = 0x828;
#else
constexpr auto MITIGATION_OFFSET = 0x9d0;
#endif

#else
// x86 offsets

#if WINDOWS_REVISION >= 2004
constexpr auto MITIGATION_OFFSETT 0x490
#elif WINDOWS_REVISION >= 1903
constexpr auto MITIGATION_OFFSETT 0x450
#elif WINDOWS_REVISION >= 1803
constexpr auto MITIGATION_OFFSETT 0x3e0
#elif WINDOWS_REVISION >= 1709
constexpr auto MITIGATION_OFFSETT 0x3d8
#else
constexpr auto MITIGATION_OFFSETT 0x490
#endif

#endif

struct mitigation_flags1
{
	ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
	ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
	ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
	ULONG DisallowStrippedImages : 1;                                 //0x9d0
	ULONG ForceRelocateImages : 1;                                    //0x9d0
	ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
	ULONG StackRandomizationDisabled : 1;                             //0x9d0
	ULONG ExtensionPointDisable : 1;                                  //0x9d0
	ULONG DisableDynamicCode : 1;                                     //0x9d0
	ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
	ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
	ULONG AuditDisableDynamicCode : 1;                                //0x9d0
	ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
	ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
	ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
	ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
	ULONG DisableNonSystemFonts : 1;                                  //0x9d0
	ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
	ULONG PreferSystem32Images : 1;                                   //0x9d0
	ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
	ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
	ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
	ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
	ULONG SignatureMitigationOptIn : 1;                               //0x9d0
	ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
	ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
	ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
	ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
	ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
	ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
	ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
	ULONG IsolateSecurityDomain : 1;                                  //0x9d0
};

struct mitigation_flags2
{
	ULONG EnableExportAddressFilter : 1;                              //0x9d4
	ULONG AuditExportAddressFilter : 1;                               //0x9d4
	ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
	ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
	ULONG EnableRopStackPivot : 1;                                    //0x9d4
	ULONG AuditRopStackPivot : 1;                                     //0x9d4
	ULONG EnableRopCallerCheck : 1;                                   //0x9d4
	ULONG AuditRopCallerCheck : 1;                                    //0x9d4
	ULONG EnableRopSimExec : 1;                                       //0x9d4
	ULONG AuditRopSimExec : 1;                                        //0x9d4
	ULONG EnableImportAddressFilter : 1;                              //0x9d4
	ULONG AuditImportAddressFilter : 1;                               //0x9d4
	ULONG DisablePageCombine : 1;                                     //0x9d4
	ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
	ULONG CetUserShadowStacks : 1;                                    //0x9d4
	ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
	ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
	ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
	ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
	ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
	ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
	ULONG BlockNonCetBinaries : 1;                                    //0x9d4
	ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
	ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
	ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
	ULONG Reserved1 : 1;                                              //0x9d4
	ULONG Reserved2 : 1;                                              //0x9d4
	ULONG Reserved3 : 1;                                              //0x9d4
	ULONG Reserved4 : 1;                                              //0x9d4
	ULONG Reserved5 : 1;                                              //0x9d4
	ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
	ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
};
