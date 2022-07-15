#include <Windows.h>
#include <cstdint>

static char g_dllPath[MAX_PATH] = {};

static void Inject(HANDLE process)
{
	void* memory = VirtualAllocEx(process, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!memory) return;

	if (!WriteProcessMemory(process, memory, g_dllPath, MAX_PATH, 0))
	{
		VirtualFreeEx(process, memory, 0, MEM_RELEASE);
		return;
	}

	HANDLE thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, memory, 0, 0);
	if (!thread || thread == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(process, memory, 0, MEM_RELEASE);
		return;
	}

	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	VirtualFreeEx(process, memory, 0, MEM_RELEASE);
}

static void WriteAbsoluteJump(void* dst, void* address)
{
#ifdef _X64BUILD
	// mov rax, address
	// jmp rax
	uint8_t codeBytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
#define ABS_JMP_ADDR_OFFSET 2
#else
	// not very efficient, uses 2 bytes more than a relative jump
	// mov eax, address
	// jmp eax
	uint8_t codeBytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
#define ABS_JMP_ADDR_OFFSET 1
#endif
	*(void**)(codeBytes + ABS_JMP_ADDR_OFFSET) = address;
	memcpy((void*)dst, codeBytes, sizeof(codeBytes));
#undef ABS_JMP_ADDR_OFFSET
}

static bool Hook(void* src, void* dst, size_t length)
{
#ifdef _X64BUILD
	if (length < 12) return false;
#else
	if (length < 7) return false;
#endif

	DWORD oldProtect;
	VirtualProtect(src, length, PAGE_EXECUTE_READWRITE, &oldProtect);

	memset(src, 0x90, length);
	WriteAbsoluteJump(src, dst);

	VirtualProtect(src, length, oldProtect, &oldProtect);

	return true;
}

static void* TrampHook(void* src, void* dst, size_t length)
{
#ifdef _X64BUILD
#define HOOK_JMP_LEN 12
#else
#define HOOK_JMP_LEN 7
#endif

	if (length < HOOK_JMP_LEN) return nullptr;

	void* gateway = VirtualAlloc(0, length + HOOK_JMP_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!gateway) return nullptr;
	memcpy(gateway, src, length);

	WriteAbsoluteJump((char*)gateway + length, (char*)src + HOOK_JMP_LEN);

	if (Hook(src, dst, length))
		return gateway;

	return nullptr;
#undef HOOK_JMP_LEN
}

enum NTTHREAD_INFORMATION_CLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
};

#define NTSETINFORMATIONTHREAD_FN(name) NTSTATUS NTAPI  name(HANDLE thread, NTTHREAD_INFORMATION_CLASS cls, LPVOID info, ULONG len)
typedef NTSETINFORMATIONTHREAD_FN(NtSetInformationThread_fn);
static NtSetInformationThread_fn* g_originalNtSetInformationThread = nullptr;

static NTSETINFORMATIONTHREAD_FN(hkNtSetInformationThread)
{
	if (cls == ThreadHideFromDebugger)
	{
		// make sure the handle is valid, harder to detect this hook.
		if (WaitForSingleObject(thread, 0) != WAIT_FAILED)
		{
			return 0; // NTSTATUS_SUCCESS
		}
	}
	return g_originalNtSetInformationThread(thread, cls, info, len);
}

#define CREATEPROCESSA_FN(name) BOOL WINAPI name(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
typedef CREATEPROCESSA_FN(CreateProcessA_fn);
static CreateProcessA_fn* g_originalCreateProcessA = nullptr;

static CREATEPROCESSA_FN(hkCreateProcessA)
{
	bool suspend = (dwCreationFlags & CREATE_SUSPENDED) != 0;
	dwCreationFlags |= CREATE_SUSPENDED;

	BOOL retval = g_originalCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if (retval)
	{
		Inject(lpProcessInformation->hProcess);

		if (!suspend)
		{
			ResumeThread(lpProcessInformation->hThread);
		}
	}

	return retval;
}

#define CREATEPROCESSW_FN(name) BOOL WINAPI name(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
typedef CREATEPROCESSW_FN(CreateProcessW_fn);
static CreateProcessW_fn* g_originalCreateProcessW = nullptr;

static CREATEPROCESSW_FN(hkCreateProcessW)
{
	bool suspend = (dwCreationFlags & CREATE_SUSPENDED) != 0;
	dwCreationFlags |= CREATE_SUSPENDED;

	BOOL retval = g_originalCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if (retval)
	{
		Inject(lpProcessInformation->hProcess);

		if (!suspend)
		{
			ResumeThread(lpProcessInformation->hThread);
		}
	}

	return retval;
}

void AntiDebugHook()
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (!ntdll) return;

	NtSetInformationThread_fn* NtSetInformationThread = (NtSetInformationThread_fn*)GetProcAddress(ntdll, "ZwSetInformationThread");
	if (!NtSetInformationThread) return;
	g_originalNtSetInformationThread = (NtSetInformationThread_fn*)TrampHook(NtSetInformationThread, hkNtSetInformationThread, 0x0F);

	g_originalCreateProcessA = (CreateProcessA_fn*)TrampHook(&CreateProcessA, hkCreateProcessA, 0x0C);
	g_originalCreateProcessW = (CreateProcessW_fn*)TrampHook(&CreateProcessW, hkCreateProcessW, 0x0C);
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		GetModuleFileNameA(module, g_dllPath, MAX_PATH);
		AntiDebugHook();
	}

	return TRUE;
}
