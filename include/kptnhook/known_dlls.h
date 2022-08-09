#pragma once
#include <ntifs.h>
#include <arch.h>

NTSTATUS remove_known_dll(const UNICODE_STRING* filename, bool native_arch);
NTSTATUS add_known_dll(const UNICODE_STRING* filename, arch a);