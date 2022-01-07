#pragma once
#include <Windows.h>

void** FindImagePointer(void* Library, UINT8* Pattern, UINT64 Size, void** Return);