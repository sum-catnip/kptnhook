#pragma once
#include <ntifs.h>

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path);
void NTAPI unload(PDRIVER_OBJECT drv);