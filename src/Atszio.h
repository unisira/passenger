#pragma once

#include <Windows.h>

/// Copys the contents of `PhysAddr` into the buffer in `Dst`
BOOLEAN AtszioReadPhysAddr(HANDLE Device, UINT64 PhysAddr, PVOID Dst, UINT32 Size);

/// Copys the contents of `Src` into the physical address `PhysAddr`
BOOLEAN AtszioWritePhysAddr(HANDLE Device, UINT64 PhysAddr, PVOID Src, UINT32 Size);

/// Allocate a buffer contiguous memory in kernel space of size `Size`
UINT64 AtszioAllocateContigMemory(HANDLE Device, UINT32 Size);

/// Free allocated contiguous memory
VOID AtszioFreeContigMemory(HANDLE Device, UINT64 VirtAddr);
