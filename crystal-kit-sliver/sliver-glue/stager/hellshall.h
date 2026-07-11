/*
 * hellshall.h — indirect-syscall resolver for NtProtectVirtualMemory.
 *
 * FetchNtProtectSyscall() walks the loader list, hashes ntdll's export table
 * to locate NtProtectVirtualMemory, extracts the SSN from the stub prologue,
 * and picks a random syscall gadget address inside ntdll.
 *
 * HhNtProtectVirtualMemory() is a naked stub that loads the SSN into eax and
 * jumps to the gadget — the syscall executes from ntdll's address space.
 */

#pragma once
#include <windows.h>

BOOL FetchNtProtectSyscall(void);

NTSTATUS HhNtProtectVirtualMemory(HANDLE ProcessHandle,
                                  PVOID *BaseAddress,
                                  PSIZE_T RegionSize,
                                  ULONG NewProtect,
                                  PULONG OldProtect);
