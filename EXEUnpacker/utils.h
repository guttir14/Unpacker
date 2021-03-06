#pragma once
#include <Windows.h>

#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))

void** FindImagePointer(void* Library, UINT8* Pattern, UINT64 Size, void** Return);
void* FindExportFinction(void* Library, const char* Name, WORD Ordinal);
bool FindFunctionName(void* Library, void* Function, char** Name);