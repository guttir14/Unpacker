#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Loader Packed.exe EXEUnpacker.dll
int Entry() {

	int argc;
	wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 3) return 1;

	STARTUPINFOW info;
	PROCESS_INFORMATION pi;
	HANDLE remote;
	HANDLE std;
	void* data;

	memset(&info, 0, sizeof(info));
	info.cb = sizeof(info);
	memset(&pi, 0, sizeof(pi));
	if (CreateProcessW(argv[1], 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &info, &pi)) {

		data = VirtualAllocEx(pi.hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!data) goto mark1;

		if (!WriteProcessMemory(pi.hProcess, data, argv[2], (wcslen(argv[2]) + 1) * 2, 0)) goto mark1;
		
		remote = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, data, 0, 0);
		if (!remote) goto mark1;
		
		WaitForSingleObject(remote, INFINITE);

		std = GetStdHandle(STD_INPUT_HANDLE);
		FlushConsoleInputBuffer(std);
		WaitForSingleObject(std, INFINITE);
		FlushConsoleInputBuffer(std);

		ResumeThread(pi.hThread);
		goto mark2;
	mark1:
		TerminateProcess(pi.hProcess, STATUS_ACCESS_VIOLATION);
	mark2:

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	return 0;
}