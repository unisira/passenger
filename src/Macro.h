#pragma once

#define RVA_PTR(Addr, Offs) ((PVOID)((PCHAR)(Addr) + (INT64)(Offs)))
#define RVA_PTR_T(T, Addr, Offs) ((T *)RVA_PTR((Addr), (Offs)))

#define RVA(Addr, Offs) ((UINT64)RVA_PTR((Addr), (Offs)))

#define GB(N) ((UINT64)(N) * 1024 * 1024 * 1024)
#define MB(N) ((UINT64)(N) * 1024 * 1024)
#define KB(N) ((UINT64)(N) * 1024)
#define PAGE_SIZE (4096)
#define PAGE_FRAME_NUMBER(Addr) ((UINT64)(Addr) >> 12)
#define PAGE_ADDRESS(Pfn) ((UINT64)(Pfn) << 12)
#define PAGE_ALIGN(Addr) ((UINT64)(Addr) & ~0xFFFULL)
#define PAGE_OFFSET(Addr) ((UINT64)(Addr) & 0xFFFULL)
#define LARGE_PAGE_OFFSET(Addr) ((UINT64)(Addr) & (0x1FFFFFULL))
#define SUPER_PAGE_OFFSET(Addr) ((UINT64)(Addr) & (0x3FFFFFFFULL))
