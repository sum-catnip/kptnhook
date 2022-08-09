#pragma once
#include <ntifs.h>

constexpr UINT8 stub64[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };
constexpr auto STUB_SIZE64 = sizeof(stub64) + sizeof(UINT64);

constexpr UINT8 stub32[] = { 0xe9 };
constexpr auto STUB_SIZE32 = sizeof(stub32) + sizeof(UINT32);

#ifdef ARR_SHELLCODE32
#else
#define ARR_SHELLCODE32 { 0 }
#error shellcode not defined, use the cmake build as it defined this
#endif

#ifdef ARR_SHELLCODE64
#else
#define ARR_SHELLCODE64 { 0 }
#error shellcode not defined, use the cmake build as it defined this
#endif

void hook64(void* func, void* target);
void hook32(void* func, void* target);