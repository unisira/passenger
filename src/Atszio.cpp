#include "Atszio.h"
#include "Macro.h"

#define IOCTL_ATSZIO_MAP_PHYS_ADDR ((DWORD)0x8807200C)
#define IOCTL_ATSZIO_UNMAP_PHYS_ADDR ((DWORD)0x88072010)
#define IOCTL_ATSZIO_READ_MSR ((DWORD)0x88070F88)
#define IOCTL_ATSZIO_WRITE_MSR ((DWORD)0x88070F8C)
#define IOCTL_ATSZIO_ALLOCATE_CONTIG ((DWORD)0x88070F90)
#define IOCTL_ATSZIO_FREE_CONTIG ((DWORD)0x88070F94)

typedef struct _ATSZIO_MAP_PHYS_ADDR
{
	UINT64 Unknown1;
	HANDLE SectionHandle;
	UINT32 Size;
	UINT64 PhysAddr;
	PVOID MappedAddr;
} ATSZIO_MAP_PHYS_ADDR, *PATSZIO_MAP_PHYS_ADDR;

typedef struct _ATSZIO_MSR_ACCESS
{
	UINT64 Msr;
	UINT64 Value;
} ATSZIO_MSR_ACCESS, *PATSZIO_MSR_ACCESS;

typedef struct _ATSZIO_ALLOC_CONTIG
{
	UINT64 Unk1;
	UINT64 Unk2;
	UINT32 Size;
	UINT64 PhysAddr;
	UINT64 VirtAddr;
	UCHAR Data[0x1000];
} ATSZIO_ALLOC_CONTIG, *PATSZIO_ALLOC_CONTIG;

BOOLEAN
AtszioReadPhysAddr(HANDLE Device, UINT64 PhysAddr, PVOID Dst, UINT32 Size)
{
	DWORD BytesReturned = 0;
	// Both map and unmap use the same request structure
	ATSZIO_MAP_PHYS_ADDR MapRequest = {
		.Size = Size,
		.PhysAddr = PAGE_ALIGN(PhysAddr),
	};

	if (!DeviceIoControl(
		    Device, IOCTL_ATSZIO_MAP_PHYS_ADDR, &MapRequest, sizeof(MapRequest), &MapRequest, sizeof(MapRequest), &BytesReturned,
		    NULL))
		return FALSE;

	memcpy(Dst, RVA_PTR(MapRequest.MappedAddr, PAGE_OFFSET(PhysAddr)), MapRequest.Size);

	if (!DeviceIoControl(
		    Device, IOCTL_ATSZIO_UNMAP_PHYS_ADDR, &MapRequest, sizeof(MapRequest), &MapRequest, sizeof(MapRequest), &BytesReturned,
		    NULL))
		return FALSE;

	return TRUE;
}

BOOLEAN
AtszioWritePhysAddr(HANDLE Device, UINT64 PhysAddr, PVOID Src, UINT32 Size)
{
	DWORD BytesReturned = 0;
	// Both map and unmap use the same request structure
	ATSZIO_MAP_PHYS_ADDR MapRequest = {
		.Size = Size,
		.PhysAddr = PAGE_ALIGN(PhysAddr),
	};

	if (!DeviceIoControl(
		    Device, IOCTL_ATSZIO_MAP_PHYS_ADDR, &MapRequest, sizeof(MapRequest), &MapRequest, sizeof(MapRequest), &BytesReturned,
		    NULL))
		return FALSE;

	memcpy(RVA_PTR(MapRequest.MappedAddr, PAGE_OFFSET(PhysAddr)), Src, MapRequest.Size);

	if (!DeviceIoControl(
		    Device, IOCTL_ATSZIO_UNMAP_PHYS_ADDR, &MapRequest, sizeof(MapRequest), &MapRequest, sizeof(MapRequest), &BytesReturned,
		    NULL))
		return FALSE;

	return TRUE;
}

UINT64
AtszioAllocateContigMemory(HANDLE Device, UINT32 Size)
{
	DWORD BytesReturned = 0;
	// Both allocate and free use the same request structure
	ATSZIO_ALLOC_CONTIG AllocRequest = { .Size = Size };

	if (!DeviceIoControl(
		    Device, IOCTL_ATSZIO_ALLOCATE_CONTIG, &AllocRequest, sizeof(AllocRequest), &AllocRequest, sizeof(AllocRequest),
		    &BytesReturned, NULL))
		return NULL;

	return AllocRequest.VirtAddr;
}

VOID
AtszioFreeContigMemory(HANDLE Device, UINT64 VirtAddr)
{
	DWORD BytesReturned = 0;
	// Both allocate and free use the same request structure
	ATSZIO_ALLOC_CONTIG AllocRequest = { .VirtAddr = VirtAddr };

	DeviceIoControl(
		Device, IOCTL_ATSZIO_FREE_CONTIG, &AllocRequest, sizeof(AllocRequest), &AllocRequest, sizeof(AllocRequest), &BytesReturned,
		NULL);
}
