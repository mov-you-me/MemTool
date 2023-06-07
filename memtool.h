#ifndef __MEMTOOL_H__
#define __MEMTOOL_H__

#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcessId(const wchar_t *process_name);

uintptr_t GetModuleBaseAddress(DWORD process_id, const wchar_t *module_name);

uintptr_t GetDynamicAddress(HANDLE process_handle, uintptr_t static_address, std::vector<unsigned int> offsets);

void PatchEx(BYTE *dst, BYTE *src, unsigned int size, HANDLE process_handle);

void NopEx(BYTE *dst, unsigned int size, HANDLE process_handle);

#endif