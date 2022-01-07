#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>
#include <HookLib.h>
#include "utils.h"

static wchar_t ImagePath[0x100];
static void* ImageStart;
static void* CopyStart;
static UINT64 ImageSize;
static void* PackedStart;
static UINT64 PackedSize;

struct {
	UINT64 TEXT : 1;
	UINT64 DATA : 1;
	UINT64 RDATA : 1;
	UINT64 PDATA : 1;
	UINT64 RSRC : 1;
	UINT64 RELOC : 1;
} SN;

#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))


static __declspec(noreturn) void Dump() {

	DWORD oldProtect;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)CopyStart + ((PIMAGE_DOS_HEADER)CopyStart)->e_lfanew);

	nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;
	

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((UINT64)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

	//DWORD rdata = 0;

	for (UINT32 i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		section->PointerToRawData = section->VirtualAddress;
		section->SizeOfRawData = ALIGN_UP_BY(section->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
		if (*section->Name != '.') {
			switch (section->Characteristics) {
			case 0x60000020:
				if (!SN.TEXT) {
					SN.TEXT = 1;
					memcpy(section->Name, ".text", 6);
				}
				break;
			case 0xC0000040:
				if (!SN.DATA) {
					SN.DATA = 1;
					memcpy(section->Name, ".data", 6);
				}
				break;
			case 0x40000040:
				if (!SN.RDATA) {
					SN.RDATA = 1;
					//rdata = section->VirtualAddress;
					memcpy(section->Name, ".rdata", 7);
					break;
				}
				if (!SN.PDATA) {
					SN.PDATA = 1;
					memcpy(section->Name, ".pdata", 7);
					break;
				}
				if (!SN.RSRC) {
					SN.RSRC = 1;
					memcpy(section->Name, ".rsrc", 6);
					break;
				}
				break;
			case 0x42000040:
				if (!SN.RELOC) {
					SN.RELOC = 1;
					memcpy(section->Name, ".reloc", 7);
				}
				break;
			}
		}
	}

	VirtualProtect(ImageStart, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect);
	memcpy(ImageStart, CopyStart, nt->OptionalHeader.SizeOfHeaders);

	// todo: restore imports
	//if (rdata) {
	//	
	//}

	wchar_t* ext = wcsrchr(ImagePath, L'.') + 1;
	wcscpy(ext + 9, ext);
	memcpy(ext, L"unpacked.", 18);
	HANDLE file = CreateFileW(ImagePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	WriteFile(file, ImageStart, ImageSize, 0, 0);
	CloseHandle(file);
	ExitProcess(0);
}


LONG Handler(EXCEPTION_POINTERS* ExceptionInfo) {

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
		
		UINT64 rip = (UINT64)ExceptionInfo->ContextRecord->Rip;
		if (rip >= (UINT64)PackedStart && rip < (UINT64)PackedStart + PackedSize) {
			DWORD oep = rip - (UINT64)ImageStart;
			PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)CopyStart + ((PIMAGE_DOS_HEADER)CopyStart)->e_lfanew);
			nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;
			nt->OptionalHeader.AddressOfEntryPoint = oep;
			ExceptionInfo->ContextRecord->Rip = (DWORD64)Dump;
			return EXCEPTION_CONTINUE_EXECUTION;
			
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

static bool (*__fastcall LdrpCallInitRoutine)(void*, void*, UINT32, void*);
static bool (*__fastcall LdrpCallInitRoutineOriginal)(void*, void*, UINT32, void*);

static void* LdrpCallInitRoutineReturn;

static bool __fastcall LdrpCallInitRoutineHook(void* Unknown1, void* DllBase, UINT32 Reason, void* Unknown2) {
	wchar_t buffer[0x100];
	DWORD oldProtect;

	if (_ReturnAddress() == LdrpCallInitRoutineReturn && 
		K32GetModuleBaseNameW((void*)-1, (HMODULE)DllBase, buffer, 0x100) &&
		wcsstr(ImagePath, buffer)) {
		unhook(LdrpCallInitRoutineOriginal);
	
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)DllBase + ((PIMAGE_DOS_HEADER)DllBase)->e_lfanew);
		
		ImageStart = DllBase;
		ImageSize = nt->OptionalHeader.SizeOfImage;

		CopyStart = HeapAlloc(GetProcessHeap(), 0, ImageSize);
		if (!CopyStart) ExitProcess(0);
		memcpy(CopyStart, ImageStart, ImageSize);

		PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((UINT64)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
		PackedStart = (UINT8*)ImageStart + section->VirtualAddress;
		PackedSize = ALIGN_UP_BY(section->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
		VirtualProtect(PackedStart, PackedSize, PAGE_READWRITE, &oldProtect);
		AddVectoredExceptionHandler(1, Handler);

		LdrpCallInitRoutine(Unknown1, DllBase, Reason, Unknown2);
		Dump();

	}

	return LdrpCallInitRoutineOriginal(Unknown1, DllBase, Reason, Unknown2);

}

void __declspec(noreturn) Load(wchar_t* Path) {
	LoadLibraryW(Path);
}

int Entry() {
	int argc;
	wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 2) return 1;
	void* ntdll = GetModuleHandleA("NTDLL");
	UINT8 pattern[]{ 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x53, 0x30, 0x49, 0x8B, 0xCD, 0xE8 };
	LdrpCallInitRoutine = (decltype(LdrpCallInitRoutine))FindImagePointer(ntdll, pattern, sizeof(pattern), &LdrpCallInitRoutineReturn);
	if (!LdrpCallInitRoutine) return 1;
	LdrpCallInitRoutineOriginal = (decltype(LdrpCallInitRoutineOriginal))hook(LdrpCallInitRoutine, LdrpCallInitRoutineHook);
	wcscpy(ImagePath, argv[1]);
	Load(ImagePath);
}