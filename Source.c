// This program will mark any process on the system as critical, which means as soon as the process exits, the machine will crash
// (or break into a debugger if one is attached.)
// Written by Joseph Ryan Ries, 2022
// This is NOT supported by Microsoft in any way. Use at your own risk.

#include <Windows.h>

#include <stdio.h>

typedef enum _PROCESSINFOCLASS
{
	ProcessBreakOnTermination = 29

} PROCESSINFOCLASS;

typedef long (WINAPI* _NtSetInformationProcess) (IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength);

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	UNREFERENCED_PARAMETER(envp);

	int Result = ERROR_SUCCESS;

	int ProcessID = 0;

	HANDLE ProcessHandle = NULL;

	ULONG Enable = 1;

	LUID Luid = { 0 };

	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	HANDLE CurrentProcessTokenHandle = NULL;

	if (argc != 2)
	{
		wprintf_s(L"\nUSAGE: SetProcessCritical <pid>\n\nMarks the process as critical.\n");

		goto Exit;
	}

	if ((ProcessID = _wtoi(argv[1])) == 0)
	{
		wprintf_s(L"\nERROR: Unable to convert %s to process ID!\n", argv[1]);

		goto Exit;
	}

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentProcessTokenHandle) == 0)
	{
		Result = GetLastError();

		wprintf(L"\nERROR: OpenProcessToken failed with error 0x%08x!\n", Result);

		goto Exit;
	}

	LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid);

	TokenPrivileges.PrivilegeCount = 1;

	TokenPrivileges.Privileges[0].Luid = Luid;

	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(
		CurrentProcessTokenHandle,
		FALSE,
		&TokenPrivileges,
		0,
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL) == 0)
	{
		Result = GetLastError();

		wprintf(L"\nERROR: AdjustTokenPrivileges failed with error 0x%08x!\n", Result);

		goto Exit;
	}

	if ((ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID)) == NULL)
	{
		Result = GetLastError();

		wprintf_s(L"\nERROR: OpenProcess failed with 0x%08x!\n", Result);

		goto Exit;
	}

	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtSetInformationProcess");
	
	if (NtSetInformationProcess == NULL)
	{
		Result = GetLastError();

		wprintf_s(L"\nERROR: GetProcAddress failed with 0x%08x!\n", Result);

		goto Exit;
	}

	Result = NtSetInformationProcess(ProcessHandle, ProcessBreakOnTermination, &Enable, sizeof(Enable));

	if (Result == 0)
	{
		wprintf_s(L"\nSUCCESS!\n");
	}
	else
	{
		wprintf_s(L"\nFailed with result 0x%x!\n", Result);
	}

Exit:	

	return(Result);
}