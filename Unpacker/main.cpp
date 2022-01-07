#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
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

struct {
	void* Heap = nullptr;
	wchar_t* Buffer = nullptr;
	DWORD Len = 0;
	DWORD Size = 0;
} IO;


struct {
	void* Handle;
	CONTEXT BackContext;
	void* Function;
} VEH2;

// Jump back where we started once
static void RestoreContext(EXCEPTION_POINTERS* ExceptionInfo) {
	*ExceptionInfo->ContextRecord = VEH2.BackContext;
	RemoveVectoredExceptionHandler(VEH2.Handle);
	VEH2.Handle = 0;
}

LONG Handler2(EXCEPTION_POINTERS* ExceptionInfo) {
	DWORD oldProtect;

	// Saving out return context
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
		ExceptionInfo->ContextRecord->Rip += 2;
		VEH2.BackContext = *ExceptionInfo->ContextRecord;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Make zombie thread
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Zombie until real call
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

		UINT64 rip = (UINT64)ExceptionInfo->ContextRecord->Rip;
		if (rip >= (UINT64)ImageStart && rip < (UINT64)ImageStart + ImageSize) {
			ExceptionInfo->ContextRecord->EFlags |= 0x100; // Still zombie...
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// Real call 
		// (Or at least first call outside protected module) <- todo: fix this
		VEH2.Function = (void*)rip;
		RestoreContext(ExceptionInfo);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Fck...
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
		RestoreContext(ExceptionInfo);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	
	return EXCEPTION_CONTINUE_SEARCH;
}

static void ScanImports(void* Start, void* End) {
	DWORD oldProtect;
	MEMORY_BASIC_INFORMATION mbi;
	wchar_t buffer[0x100];
	char* name;
	if (!IO.Buffer) {
		IO.Heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
		if (!IO.Heap) ExitProcess(1);
		IO.Size = 0x00008000;
		IO.Buffer = (wchar_t*)HeapAlloc(IO.Heap, 0, IO.Size);
		if (!IO.Buffer) return;
	}
	for (void** it = (void**)Start; it < End; it++) {
		void* value = *it;
		start:
		
		if (!VirtualQuery(value, &mbi, sizeof(mbi)) || !mbi.AllocationBase || mbi.Type != MEM_IMAGE || (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0) continue;
		if (!K32GetModuleBaseNameW((void*)-1, (HMODULE)mbi.AllocationBase, buffer, 0x100)) continue;

		if (mbi.AllocationBase == ImageStart) {
			VEH2.Handle = AddVectoredExceptionHandler(1, Handler2);
			VirtualProtect(mbi.BaseAddress, 0x10, mbi.Protect | PAGE_GUARD, &oldProtect);
			__ud2();
			if (VEH2.Handle) {
				VEH2.Function = 0;
				((void(*)())value)();
			}
			VirtualProtect(mbi.BaseAddress, oldProtect, mbi.Protect, &oldProtect); // Just to be sure
			if (VEH2.Function) {
				value = VEH2.Function;
				goto start;
			}
		}

		if (FindFunctionName(mbi.AllocationBase, value, &name)) {
			IO.Len += _swprintf(IO.Buffer + IO.Len, L"%p\t%p\t%ws!%S\n", it, (UINT8*)it - (UINT64)ImageStart, buffer, name);
		}
		else {
			IO.Len += _swprintf(IO.Buffer + IO.Len, L"%p\t%p\t%ws!%p\n", it, (UINT8*)it - (UINT64)ImageStart, buffer, (UINT8*)value - (UINT64)mbi.AllocationBase);
		}

		if (IO.Len * 2 > IO.Size - 0x2000) {
			IO.Size += 0x8000;
			void* buf = HeapReAlloc(IO.Heap, 0, IO.Buffer, IO.Size);
			if (!buf) {
				buf = HeapAlloc(IO.Heap, 0, IO.Size);
				if (!buf) ExitProcess(1);
				memcpy(buf, IO.Buffer, IO.Len * 2);
				HeapFree(IO.Heap, 0, IO.Buffer);
			}
			IO.Buffer = (wchar_t*)buf;
		}

	}
}

static void SaveImports(const wchar_t* Path) {
	if (IO.Buffer) {
		HANDLE file = CreateFileW(Path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		WriteFile(file, IO.Buffer, IO.Len * 2, 0, 0);
		CloseHandle(file);
	}
	if (IO.Heap) {
		HeapDestroy(IO.Heap);
	}
}


static __declspec(noreturn) void Dump() {

	DWORD oldProtect;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)CopyStart + ((PIMAGE_DOS_HEADER)CopyStart)->e_lfanew);

	nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((UINT64)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

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
		if (strcmp((char*)section->Name, ".data") == 0 || strcmp((char*)section->Name, ".rdata") == 0) {
			UINT8* start = (UINT8*)ImageStart + section->VirtualAddress;
			UINT8* end = start + ALIGN_UP_BY(section->Misc.VirtualSize, 8);
			ScanImports(start, end);
		}
	}

	VirtualProtect(ImageStart, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect);
	memcpy(ImageStart, CopyStart, nt->OptionalHeader.SizeOfHeaders);

	wchar_t* ext = wcsrchr(ImagePath, L'.') + 1;
	wcscpy(ext + 9, ext);
	memcpy(ext, L"unpacked.", 18);
	HANDLE file = CreateFileW(ImagePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	WriteFile(file, ImageStart, ImageSize, 0, 0);
	CloseHandle(file);

	memcpy(ext, L"imports.txt", 24);
	SaveImports(ImagePath);

	ExitProcess(0);
}

struct {
	void* Handle;
} VEH1;

LONG Handler1(EXCEPTION_POINTERS* ExceptionInfo) {
	DWORD oldProtect;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
		
		UINT64 rip = (UINT64)ExceptionInfo->ContextRecord->Rip;
		if (rip >= (UINT64)PackedStart && rip < (UINT64)PackedStart + PackedSize) {
			VirtualProtect(PackedStart, PackedSize, PAGE_EXECUTE_READ, &oldProtect);
			DWORD oep = rip - (UINT64)ImageStart;
			PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)CopyStart + ((PIMAGE_DOS_HEADER)CopyStart)->e_lfanew);
			nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;
			nt->OptionalHeader.AddressOfEntryPoint = oep;
			ExceptionInfo->ContextRecord->Rip = (DWORD64)Dump;
			RemoveVectoredExceptionHandler(VEH1.Handle);
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
		VEH1.Handle = AddVectoredExceptionHandler(1, Handler1);

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