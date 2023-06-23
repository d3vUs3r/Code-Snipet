#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
	DWORD processId = GetCurrentProcessId(); // The process ID of the target process
	HANDLE hProcess = NULL; // Handle to the target process
	HANDLE DllFile = NULL; //  Handle to the DLL File
	
	PVOID dllPathAddr{ nullptr };
	LPVOID lpBuffer{ nullptr };

	// Attempt to attach to the process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		std::cout << "Failed to attach to the process. Error code: " << GetLastError() << std::endl;
		return 1;
	}

	// Process attached successfully
	std::cout << "Attached to the process successfully!" << std::endl;

	wchar_t dllPath[] = TEXT("C:\\Users\\root\\Source\\Repos\\TestLearn\\Release\\T1546.010.dll");
	
	// Open the DLL file
	DllFile = CreateFileW(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DllFile == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open the DLL file. Error code: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	// Get the size of the DLL file
	DWORD fileSize = GetFileSize(DllFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		std::cout << "Failed to get the DLL file size. Error code: " << GetLastError() << std::endl;
		CloseHandle(DllFile);
		CloseHandle(hProcess);
		return 1;
	}

	// Allocate memory within the target process
	dllPathAddr = VirtualAllocEx(hProcess, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dllPathAddr == NULL) {
		std::cout << "Failed to allocate memory within the process. Error code: " << GetLastError() << std::endl;
		CloseHandle(DllFile);
		CloseHandle(hProcess);
		return 1;
	}

	// Allocate memory in the local process
	lpBuffer = HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (lpBuffer == NULL) {
		std::cout << "Failed to allocate memory in the local process. Error code: " << GetLastError() << std::endl;
		CloseHandle(DllFile);
		CloseHandle(hProcess);
		return 1;
	}

	// Read the DLL binary into the local buffer
	DWORD bytesRead = 0;
	if (!ReadFile(DllFile, lpBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		std::cout << "Failed to read the DLL file. Error code: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, lpBuffer);
		VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
		CloseHandle(DllFile);
		CloseHandle(hProcess);
		return 1;
	}

	// Write the DLL binary into the allocated memory in the target process
	if (!WriteProcessMemory(hProcess, dllPathAddr, lpBuffer, fileSize, NULL)) {
		std::cout << "Failed to write DLL binary into process memory. Error code: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, lpBuffer);
		VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
		CloseHandle(DllFile);
		CloseHandle(hProcess);
		return 1;
	}

	/* code to continue */
	
	// DLL loaded successfully
	std::cout << "DLL loaded into process memory successfully!" << std::endl;

	// Free the local buffer
	HeapFree(GetProcessHeap(), 0, lpBuffer);

	// Close the DLL file handle
	CloseHandle(DllFile);


	//free the allocated memory
	VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);

	CloseHandle(hProcess);

	return 0;
}
