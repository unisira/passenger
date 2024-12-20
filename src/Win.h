#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <Winnt.h>

typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracepoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31,
	SysDbgRegisterForUmBreakInfo = 32,
	SysDbgGetUmBreakPid = 33,
	SysDbgClearUmBreakPid = 34,
	SysDbgGetUmAttachPid = 35,
	SysDbgClearUmAttachPid = 36,
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

typedef struct _SYSDBG_TRIAGE_DUMP {
	ULONG Flags;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParam1;
	ULONG_PTR BugCheckParam2;
	ULONG_PTR BugCheckParam3;
	ULONG_PTR BugCheckParam4;
	ULONG ProcessHandles;
	ULONG ThreadHandles;
	PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, *PSYSDBG_TRIAGE_DUMP;

typedef struct _DUMP_HEADER64 {
	DWORD Signature;
	DWORD ValidDump;
	DWORD NtMajorVersion;
	DWORD NtMinorVersion;
	UINT64 DirectoryTableBase;
	UINT64 MmPfnDatabase;
	UINT64 PsLoadedModuleList;
	UINT64 PsActiveProcessHead;
	UINT32 Machine;
	UINT32 ActiveProcessorCount;
} DUMP_HEADER64, *PDUMP_HEADER64;

typedef union _MM_LA48 {
	UINT64 Value;

	struct {
		UINT64 PageOffset : 12;
		UINT64 PtIndex : 9;
		UINT64 PdIndex : 9;
		UINT64 PdptIndex : 9;
		UINT64 Pml4Index : 9;
		UINT64 Reserved1 : 16;
	};
} MM_LA48, *PMM_LA48;

typedef union _MM_PTE {
	UINT64 Value;

	struct {
		UINT64 Present : 1;
		UINT64 WriteAllowed : 1;
		UINT64 SupervisorOwned : 1;
		UINT64 WriteThrough : 1;
		UINT64 CacheDisable : 1;
		UINT64 Accessed : 1;
		UINT64 Dirty : 1;
		UINT64 LargePage : 1;
		UINT64 Global : 1;
		UINT64 Ignored1 : 3; // Windows has Write (1), CoW (3) here
		UINT64 PageFrameNumber : 40;
		UINT64 Ignored3 : 11;
		UINT64 ExecuteDisable : 1;
	};
} MM_PTE, *PMM_PTE;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY64 InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	union {
		USHORT SignatureLevel : 4;
		USHORT SignatureType : 3;
		USHORT Frozen : 2;
		USHORT HotPatch : 1;
		USHORT Unused : 6;
		USHORT EntireField;
	} u1;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	union {
		PVOID Spare;
		PVOID NtDataTableEntry;
	};
	ULONG SizeOfImageNotRounded;
	ULONG TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_RELOCATION_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI NtLoadDriver(_In_ PUNICODE_STRING DriverServiceName);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI NtUnloadDriver(_In_ PUNICODE_STRING DriverServiceName);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI ZwSystemDebugControl(
	IN SYSDBG_COMMAND Command, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength, OUT PULONG ReturnLength OPTIONAL);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI ZwShutdownSystem(IN SHUTDOWN_ACTION Action);
