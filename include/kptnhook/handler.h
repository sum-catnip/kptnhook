#pragma once
#include <ntifs.h>

constexpr UNICODE_STRING KNOWN_DLLS[] = {
	RTL_CONSTANT_STRING(L"pirt.dll")
};

void on_image_load(PUNICODE_STRING img_name, HANDLE proc, PIMAGE_INFO info);
void on_create_proc(HANDLE parent_pid, HANDLE pid, BOOLEAN create);