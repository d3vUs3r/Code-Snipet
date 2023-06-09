#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
	DWORD processId = GetCurrentProcessId(); // The process ID of the target process
	HANDLE hProcess = NULL; // Handle to the target process
	PVOID dllPathAddr {nullptr};

	// Attempt to attach to the process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		std::cout << "Failed to attach to the process. Error code: " << GetLastError() << std::endl;
		return 1;
	}

	// Process attached successfully
	std::cout << "Attached to the process successfully!" << std::endl;

	wchar_t dllPath[] = TEXT("C:\\Users\\root\\Source\\Repos\\TestLearn\\Release\\T1546.010.dll");
	//size_t pathLength = wcslen(dllPath);
	//SIZE_T dwSize = (pathLength + 1) * sizeof(wchar_t);

	dllPathAddr = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);


	if (dllPathAddr == NULL) {
		std::cout << "Failed to allocate memory within the process. Error code: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	// Memory allocation successful
	std::cout << "Memory allocated successfully within the process!" << std::endl;

	// Write the DLL path into the allocated memory in the target process
	if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath, sizeof(dllPath), NULL)) {
		std::cout << "Failed to write DLL path into process memory. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	// DLL path copied successfully
	std::cout << "DLL path copied into process memory successfully!" << std::endl;


	// Get the address of the LoadLibraryW function
	LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (loadLibraryAddr == NULL) {
		std::cout << "Failed to get the address of LoadLibraryW. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	// Create a remote thread in the target process to execute the DLL
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);

	// Wait for the remote thread to finish
	WaitForSingleObject(hThread, INFINITE);

	// DLL executed successfully
	std::cout << "DLL executed successfully!" << std::endl;


	// Don't forget to free the allocated memory when you're done
	VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);


	CloseHandle(hProcess);
	return 0;
}
