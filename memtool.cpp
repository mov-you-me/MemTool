#include "memtool.h"
/// @brief Get the Process Id object
/// @param process_name name of the process
/// @return process id
DWORD GetProcessId(const wchar_t *process_name)
{
    DWORD process_id = 0;
    // Create a snapshot of all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Check if the snapshot is valid
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(PROCESSENTRY32);

        // Get the first process
        if (Process32First(hSnapshot, &process_entry))
        {
            // Iterate over all processes
            do
            {
                // Check if the process name matches
                if (!_wcsicmp(process_entry.szExeFile, process_name))
                {
                    // Get the process id
                    process_id = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &process_entry));
        }
    }
    // Close the snapshot handle
    CloseHandle(hSnapshot);
    return process_id;
}

/// @brief Get the Module Base Address
/// @param process_id process id
/// @param module_name name of the module
/// @return module base address
uintptr_t GetModuleBaseAddress(DWORD process_id, const wchar_t *module_name)
{
    uintptr_t module_base_address = 0;
    // Create a snapshot of all modules in the specified process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

    // Check if the snapshot is valid
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 module_entry;
        module_entry.dwSize = sizeof(MODULEENTRY32);

        // Get the first module
        if (Module32First(hSnapshot, &module_entry))
        {
            // Iterate over all modules
            do
            {
                // Check if the module name matches
                if (!_wcsicmp(module_entry.szModule, module_name))
                {
                    // Get the module base address
                    module_base_address = (uintptr_t)module_entry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &module_entry));
        }
    }
    // Close the snapshot handle
    CloseHandle(hSnapshot);
    return module_base_address;
}

/// @brief Get the Dynamic Address object
/// @param process_handle
/// @param static_address
/// @param offsets
/// @return
uintptr_t GetDynamicAddress(HANDLE process_handle, uintptr_t static_address, std::vector<unsigned int> offsets)
{
    uintptr_t addr = static_address;
    // Iterate over all offsets
    for (unsigned int i = 0; i < offsets.size(); i++)
    {
        // Read the new static address
        ReadProcessMemory(process_handle, (BYTE *)addr, &addr, sizeof(addr), NULL);

        // Add the offset to the static address
        addr += offsets[i];
    }
    return addr;
}

/// @brief Patch the memory
/// @param dst
/// @param src
/// @param size
/// @param process_handle
void PatchEx(BYTE *dst, BYTE *src, unsigned int size, HANDLE process_handle)
{
    DWORD old_protect;
    // Change the memory protection
    VirtualProtectEx(process_handle, dst, size, PAGE_EXECUTE_READWRITE, &old_protect);

    // Write the memory
    WriteProcessMemory(process_handle, dst, src, size, nullptr);

    // Restore the memory protection
    VirtualProtectEx(process_handle, dst, size, old_protect, &old_protect);
}

/// @brief Patch the memory with NOP
/// @param dst
/// @param size
/// @param process_handle
void NopEx(BYTE *dst, unsigned int size, HANDLE process_handle)
{
    DWORD old_protect;
    // Change the memory protection
    VirtualProtectEx(process_handle, dst, size, PAGE_EXECUTE_READWRITE, &old_protect);

    // Write the memory
    memset(dst, 0x90, size);

    // Restore the memory protection
    VirtualProtectEx(process_handle, dst, size, old_protect, &old_protect);
}
