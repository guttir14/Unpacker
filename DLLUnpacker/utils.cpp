#include <windows.h>

bool PatternScan(UINT8* Data, UINT8* Pattern, UINT64 Size) {
	for (UINT64 i = 0; i < Size; i++) {
		if (Pattern[i] && Data[i] != Pattern[i]) return false;
	}
	return true;
}

void* FindSignature(void* Start, void* End, UINT8* Pattern, UINT64 Size) {
	for (UINT8* it = (UINT8*)Start; it < (UINT8*)End - Size; it++) {
		if (PatternScan(it, Pattern, Size)) return it;
	}
	return nullptr;
}

void* FindImageSignature(void* Library, UINT8* Pattern, UINT64 Size) {
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)Library + ((PIMAGE_DOS_HEADER)Library)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((UINT64)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
	for (UINT32 i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (section->Characteristics & 0x20000020) {
			UINT8* start = (UINT8*)Library + section->VirtualAddress;
			UINT8* end = start + section->Misc.VirtualSize;
			void* ptr = FindSignature(start, end, Pattern, Size);
			if (ptr) return ptr;
		}
	}
	return nullptr;
}

void** FindImagePointer(void* Library, UINT8* Pattern, UINT64 Size, void** Return) {
	void* address = FindImageSignature(Library, Pattern, Size);
	if (!address) return nullptr;
	
	UINT8 k = 1;
	UINT32 i = 0;
	for (; i < Size && k != 16; i++) {
		if (!Pattern[i]) k = k << 1;
		else k = 1;
	}
	if (i != Size) i -= 4;
	address = (UINT8*)address + i;

	if (Return) {
		*Return = (UINT8*)address + 4;
	}

	return (void**)((UINT8*)address + 4 + *(INT32*)address);
}

void* FindExportFinction(void* Library, const char* Name, WORD Ordinal) {
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)Library + ((PIMAGE_DOS_HEADER)Library)->e_lfanew);
	PIMAGE_DATA_DIRECTORY dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir->VirtualAddress) return nullptr;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((UINT64)Library + dir->VirtualAddress);
	DWORD* functions = (DWORD*)((UINT64)Library + exp->AddressOfFunctions);
	WORD* ordinals = (WORD*)((UINT64)Library + exp->AddressOfNameOrdinals);
	if (Ordinal) return (void*)((UINT64)Library + functions[ordinals[Ordinal]]);
	DWORD* names = (DWORD*)((UINT64)Library + exp->AddressOfNames);
	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		char* name = (char*)((UINT64)Library + names[i]);
		if (strcmp(name, Name) != 0) continue;
		void* function = (void*)((UINT64)Library + functions[ordinals[i]]);
		return function;
	}
	return nullptr;
}

bool FindFunctionName(void* Library, void* Function, char** Name) {
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT64)Library + ((PIMAGE_DOS_HEADER)Library)->e_lfanew);
	PIMAGE_DATA_DIRECTORY dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir->VirtualAddress) return false;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((UINT64)Library + dir->VirtualAddress);
	DWORD* functions = (DWORD*)((UINT64)Library + exp->AddressOfFunctions);
	WORD* ordinals = (WORD*)((UINT64)Library + exp->AddressOfNameOrdinals);
	DWORD* names = (DWORD*)((UINT64)Library + exp->AddressOfNames);
	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		void* function = (void*)((UINT64)Library + functions[ordinals[i]]);
		if (function != Function) continue;
		*Name = (char*)((UINT64)Library + names[i]);
		return true;
	}
	return false;
}