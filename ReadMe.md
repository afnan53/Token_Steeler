# Exploiting ThrottleStop.sys: A Windows 11 25H2 BYOVD Token Stealer
# Introduction

This write-up details the development of a Bring Your Own Vulnerable Driver (BYOVD) exploit targeting ThrottleStop.sys. The goal was to perform local privilege escalation from an Administrator context to NT AUTHORITY\SYSTEM on Windows 11 (Build 26200 / 25H2).

I chose this project to bridge the gap between my userland evasion knowledge (indirect syscalls) and kernel-level exploitation. The exploit relies on physical memory manipulation and Windows Superfetch to bypass modern memory protections like Kernel ASLR.
The Vulnerability

The vulnerable driver exposes a set of IOCTL codes that allow arbitrary physical memory read and write operations from user mode.

    Read IOCTL: 0x80006498

    Write IOCTL: 0x8000649C

Because the driver fails to validate the requested physical addresses, an attacker with Administrator privileges (and the ability to load the driver) can read and write any physical memory on the system.
The Challenge: Virtual to Physical Translation (V2P)

The most difficult part of this exploit wasn't the driver itself, but the address translation. The vulnerable IOCTLs require physical addresses, but kernel structures like the EPROCESS and variables like PsInitialSystemProcess exist at virtual addresses.

Since Windows 10 1803, MmMapIoSpace has been locked down, meaning we cannot simply map the page tables to find the physical address. To solve this, I had to leverage Windows Superfetch.
Defeating Superfetch on Windows 11

My initial attempts to query the Superfetch PFN database failed with STATUS_INVALID_PARAMETER (0xC000000D). After extensive debugging in WinDbg, I realized that modern Windows builds no longer fully support the V1 PF_MEMORY_RANGE_INFO structure.

I modified my translation logic to query V2 (Version = 2) of the memory ranges first. Once the physical memory ranges were populated, I chunked the PFN queries into blocks of 4096 pages. This successfully built a translation map of over 445,000 pages, allowing me to convert any kernel virtual address into its physical counterpart.
Finding SYSTEM and Stealing the Token

With the V2P map built, the exploitation chain was straightforward:

    Locate the Kernel Base: Used EnumDeviceDrivers to get the base address of ntoskrnl.exe.

    Resolve PsInitialSystemProcess: Calculated the RVA by loading a user-mode copy of ntoskrnl.exe and reading its export table.

    Read the SYSTEM EPROCESS: Translated the virtual address of PsInitialSystemProcess to a physical address, read the 8-byte pointer, and then translated that pointer to find the physical address of the SYSTEM EPROCESS structure.

    Extract the Token: Read the SYSTEM token pointer from EPROCESS + 0x248.



# The Final Chain

To find my own process, I walked the ActiveProcessLinks doubly-linked list starting from the SYSTEM process. Once my process's PID matched, I translated my EPROCESS to a physical address and overwrote my Token pointer with the SYSTEM token. To prevent a system crash, I carefully preserved the lower 4 bits of my old token (the reference count bits).

Finally, I spawned a reverse shell back to my listener, resulting in an NT AUTHORITY\SYSTEM shell.
Conclusion & Takeaways

This project was a massive learning experience in Windows kernel internals, specifically memory management and undocumented APIs. It taught me that exploiting a driver is only half the battle; the real challenge lies in navigating the OS's memory structures and adapting to version-specific changes in Windows.
# Disclaimer

This exploit was developed strictly for educational purposes in an isolated lab environment. Do not use this code on systems you do not own or have explicit permission to test.
