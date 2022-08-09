#include "hook.h"
#include "undocumented.h"
#include "tibpebwow64.h"
#include "pointers.h"
#include "log.h"

#include <stddef.h>
#include <ntimage.h>

template <int N>
void write_bytes(void** target, const UINT8 (&bytes)[N]) {
	memcpy(*target, bytes, sizeof(bytes));
	*reinterpret_cast<UINT8**>(target) += sizeof(bytes);
}

template <int N>
void write_str(void** target, const char(&bytes)[N]) {
	memcpy(*target, bytes, sizeof(bytes));
	*reinterpret_cast<UINT8**>(target) += sizeof(bytes);
}

template <int N>
void write_wstr(void** target, const wchar_t(&bytes)[N]) {
	memcpy(*target, bytes, sizeof(bytes));
	*reinterpret_cast<UINT8**>(target) += sizeof(bytes);
}

template <class T>
void write_type(void** target, T value) {
	**reinterpret_cast<T**>(target) = value;
	*reinterpret_cast<UINT8**>(target) += sizeof(T);
}

/// <summary>
/// hooks function to call target
/// </summary>
/// <param name="func">function to hook</param>
/// <param name="target">where to jump to</param>
void hook32(void* func, void* target) {
	void* func_start = func;

	// data "segment"

	// save original code
	void* original = target;
	memcpy(target, func, STUB_SIZE32);
	target = addroffset(void, target, STUB_SIZE32);

	void* module_file = target;
	const char module_file_str[] = "gi_agent.dll";
	write_str(&target, module_file_str);

	// overwrite original code
	// jmp shellcode
	write_bytes(&func, { 0xe9 });
	write_type<INT32>(&func, static_cast<INT32>(addr_relative_to(target, func)) - sizeof(INT32));

	// push parameters
	write_bytes(&target, { 0x68 }); // push
	write_type<UINT32>(&target, towow64(original));

	write_bytes(&target, { 0x68 }); // push
	write_type<UINT32>(&target, STUB_SIZE32);

	write_bytes(&target, { 0x68 }); // push
	write_type<UINT32>(&target, towow64(module_file));

	write_bytes(&target, { 0x68 }); // push
	write_type<UINT32>(&target, sizeof(module_file_str));

	write_bytes(&target, { 0x68 }); // push
	write_type<UINT32>(&target, towow64(func_start));

	write_bytes(&target, ARR_SHELLCODE32);
}

void hook64(void* func, void* target) {
	void* func_start = func;

	void* shellcode = target;
	write_bytes(&target, ARR_SHELLCODE64);

	// data "segment"

	// save original code
	void* original = target;
	memcpy(target, func, STUB_SIZE64);
	target = addroffset(void, target, STUB_SIZE64);

	void* module_file = target;
	const wchar_t module_file_str[] = L"gi_agent.dll";
	write_wstr(&target, module_file_str);

	// write UNICODE_STRING for module_file
	void* module_file_unicode = target;
	UNICODE_STRING module_file_unicode_str;
	// length (not including null terminator)
	module_file_unicode_str.Length = sizeof(module_file_str) - sizeof(module_file_str[0]);
	// maximum length (including null terminator)
	module_file_unicode_str.MaximumLength = sizeof(module_file_str);
	// buffer; ptr to actual wstr
	module_file_unicode_str.Buffer = reinterpret_cast<PWCH>(module_file);
	write_type<UNICODE_STRING>(&target, module_file_unicode_str);

	// shellcode stub
	void* shellcode_stub = target;

	// save volatile registers
	write_bytes(&target, { 0x50 }); // push rax
	write_bytes(&target, { 0x51 }); // push rcx
	write_bytes(&target, { 0x52 }); // push rdx
	write_bytes(&target, { 0x41, 0x50 }); // push r8
	write_bytes(&target, { 0x41, 0x51 }); // push r9
	write_bytes(&target, { 0x41, 0x52 }); // push r10
	write_bytes(&target, { 0x41, 0x53 }); // push r11

	// set parameters
	write_bytes(&target, { 0x48, 0xb9 }); // rcx = original_func*
	write_type<void*>(&target, func_start);

	write_bytes(&target, { 0x48, 0xba }); // rdx = dllname*
	write_type<void*>(&target, module_file_unicode);

	write_bytes(&target, { 0x41, 0xb8 }); // r8 = original_code_sz
	write_type<UINT32>(&target, STUB_SIZE64);

	write_bytes(&target, { 0x49, 0xb9 }); // r9 = original_code*
	write_type<void*>(&target, original);

	write_bytes(&target, { 0xe8 }); // call shellcode
	write_type<UINT32>(&target, addr_relative_to(shellcode, target) - sizeof(UINT32));

	write_bytes(&target, { 0x41, 0x5b }); // pop r11
	write_bytes(&target, { 0x41, 0x5a }); // pop r10
	write_bytes(&target, { 0x41, 0x59 }); // pop r9
	write_bytes(&target, { 0x41, 0x58 }); // pop r8
	write_bytes(&target, { 0x5a }); // pop rdx
	write_bytes(&target, { 0x59 }); // pop rcx
	write_bytes(&target, { 0x58 }); // pop rax

	// jmp back
	write_bytes(&target, stub64);
	write_type<void*>(&target, func_start);

	// overwrite original code
	// jmp shellcode
	write_bytes(&func, stub64);
	write_type<void*>(&func, shellcode_stub);
}