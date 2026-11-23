#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <winternl.h>
#include <psapi.h>
#include <unordered_map>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstddef>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

#define IOCTL_READ  0x80006498
#define IOCTL_WRITE 0x8000649C

#define OFFSET_PID   0x1d0
#define OFFSET_LINKS 0x1d8
#define OFFSET_TOKEN 0x248

enum SUPERFETCH_INFORMATION_CLASS {
    SuperFetchPfnQuery = 6,
    SuperfetchMemoryRangesQuery = 17
};

// Bitfield layout describing physical memory frame attributes.
struct MEMORY_FRAME_INFORMATION {
    ULONGLONG UseDescription : 4;
    ULONGLONG ListDescription : 3;
    ULONGLONG Reserved0 : 1;
    ULONGLONG Pinned : 1;
    ULONGLONG DontUse : 48;
    ULONGLONG Priority : 3;
    ULONGLONG Reserved : 4;
};

// Page frame identity and virtual address mapping returned by Superfetch.
struct MMPFN_IDENTITY {
    union { MEMORY_FRAME_INFORMATION e1; UINT64 pad; } u1;
    SIZE_T PageFrameIndex;
    union {
        struct { ULONG Image : 1; ULONG Mismatch : 1; } e1;
        PVOID VirtualAddress;
    } u2;
};

// Summary counters for system memory page lists and priorities.
struct SYSTEM_MEMORY_LIST_INFORMATION {
    SIZE_T    ZeroPageCount;
    SIZE_T    FreePageCount;
    SIZE_T    ModifiedPageCount;
    SIZE_T    ModifiedNoWritePageCount;
    SIZE_T    BadPageCount;
    SIZE_T    PageCountByPriority[8];
    SIZE_T    RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
};

// Request structure used to query PFN priority and mapping details.
struct PF_PFN_PRIO_REQUEST {
    ULONG                          Version;
    ULONG                          RequestFlags;
    SIZE_T                         PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
    MMPFN_IDENTITY                 PageData[1];
};

// Contiguous physical page frame range descriptor.
struct PF_PHYSICAL_MEMORY_RANGE {
    ULONG_PTR BasePfn;
    ULONG_PTR PageCount;
};

// Version 1 container for physical memory range entries.
struct PF_MEMORY_RANGE_INFO_V1 {
    ULONG Version;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
};

// Version 2 container for physical memory range entries with flags.
struct PF_MEMORY_RANGE_INFO_V2 {
    ULONG Version;
    ULONG Flags;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
};

// Control header passed to NtQuerySystemInformation for Superfetch queries.
typedef struct _SUPERFETCH_INFORMATION {
    ULONG Version;
    ULONG Magic;
    SUPERFETCH_INFORMATION_CLASS InfoClass;
    PVOID Data;
    ULONG Length;
} SUPERFETCH_INFORMATION, * PSUPERFETCH_INFORMATION;

extern std::unordered_map<uint64_t, uint64_t> g_va_to_pa;
extern HANDLE hDriver;

// Reads physical memory through the driver IOCTL interface.
bool ReadPhysical(uint64_t physAddr, void* buffer, uint32_t size);

// Writes physical memory through the driver IOCTL interface.
bool WritePhysical(uint64_t physAddr, const void* buffer, uint32_t size);

// Enables SeProfileSingleProcessPrivilege on the current process token.
bool EnableProfilePrivilege();

// Issues a Superfetch query via NtQuerySystemInformation.
NTSTATUS sfQuery(SUPERFETCH_INFORMATION_CLASS infoClass, void* buf, ULONG length, ULONG* rlen = nullptr);

// Translates a kernel virtual address to a physical address using Superfetch PFN data.
bool GetV2PTranslation(uint64_t virtualAddr, uint64_t* physicalAddr);

// Retrieves the base address of the loaded Windows kernel image.
uint64_t GetKernelBase();

// Resolves the kernel virtual address of PsInitialSystemProcess.
uint64_t GetPsInitialSystemProcessVA(uint64_t kernelBase);

// Queries system process information for the current process entry.
uint64_t GetMyEprocessViaNtQuery();