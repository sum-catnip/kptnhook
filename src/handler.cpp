#include "handler.h"
#include "log.h"
#include "raii.hpp"
#include "undocumented.h"
#include "path.h"
#include "hook.h"
#include "known_dlls.h"
#include "pointers.h"
#include "drvglobal.h"
#include "arch.h"

#include <ntimage.h>

RTL_RUN_ONCE init_native;
RTL_RUN_ONCE init_wow64;

ULONG init_lazy(PRTL_RUN_ONCE run_once, PVOID a, PVOID* ctx) {
	UNREFERENCED_PARAMETER(run_once);
	UNREFERENCED_PARAMETER(ctx);
	NTSTATUS status = STATUS_SUCCESS;

	log_debug("reg path: %wZ", GLOBAL.registry_path);
	log_debug("drv object: %p", GLOBAL.obj);

	// init known dlls
	for (const UNICODE_STRING& filename : KNOWN_DLLS)
		if (!NT_SUCCESS(add_known_dll(&filename, *reinterpret_cast<arch*>(a)))) break;

	return NT_SUCCESS(status);
}

NTSTATUS on_image_load_status(PUNICODE_STRING path, HANDLE pid, PIMAGE_INFO info) {
	NTSTATUS status = STATUS_SUCCESS;

	// only userland images
	if (info->SystemModeImage) return status;
	// we don't care about remotely loaded images
	if (PsGetCurrentProcessId() != pid) return status;
	// trigger on first k32dll load
	UNICODE_STRING k32_filename = RTL_CONSTANT_STRING(L"kernel32.dll");
	if (! match_filename(path, &k32_filename)) return status;

	PEPROCESS p;
	status = PsLookupProcessByProcessId(pid, &p);
	guard_nts(status, "failed getting PEPROCESS for pid %p; status: %lx", pid, status);
	bind_peprocess(p);

	auto a = proc_arch(p);
	switch(a.com) {
		case compat::native:
			RtlRunOnceExecuteOnce(&init_native, init_lazy, &a, nullptr);
			break;
		case compat::wow:
			RtlRunOnceExecuteOnce(&init_wow64, init_lazy, &a, nullptr);
			break;
	}

	return status;
}

NTSTATUS on_create_proc_status(HANDLE parent_pid, HANDLE pid, BOOLEAN create) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(parent_pid);

	if (!create) return status;

	PEPROCESS p;
	status = PsLookupProcessByProcessId(pid, &p);
	guard_nts(status, "failed getting PEPROCESS for pid %p; status: %lx", pid, status);
	bind_peprocess(p);

	arch a = proc_arch(p);

	// attach to target process address space
	KAPC_STATE state;
	KeStackAttachProcess(p, &state);
	bind_kapc_state(&state);

	auto base = reinterpret_cast<IMAGE_DOS_HEADER*>(PsGetProcessSectionBaseAddress(p));
	void* entrypoint = nullptr;

	// get entrypoint va
	if (a.b == bit::x32) {
		auto nt = addroffset(IMAGE_NT_HEADERS32, base, base->e_lfanew);
		entrypoint = addroffset(void, base, nt->OptionalHeader.AddressOfEntryPoint);
	}
	else {
		auto nt = addroffset(IMAGE_NT_HEADERS64, base, base->e_lfanew);
		entrypoint = addroffset(void, base, nt->OptionalHeader.AddressOfEntryPoint);
	}

	const char* procname = PsGetProcessImageFileName(p);
	log_debug("got image name for process: %s", procname);
	//if(strcmp(procname, "notepad.exe")) return status;

	mitigation_flags1* flags1 = addroffset(mitigation_flags1, p, MITIGATION_OFFSET);
	//mitigation_flags2* flags2 = addroffset(mitigation_flags2, p, MITIGATION_OFFSET + sizeof(ULONG));
	
	flags1->DisableDynamicCode = false;
	
	log_debug("disabled dynamic code mitigation policy");

	HANDLE hproc;
	status = ObOpenObjectByPointer(p, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hproc);
	guard_nts(status, "ObOpenObjectByPointer(target process) failed with %lx in process %s", status, procname);
	bind_handle(hproc);

	void* shellcode_mem = nullptr;
	SIZE_T shellcode_mem_sz = 1000;
	status = ZwAllocateVirtualMemory(hproc, &shellcode_mem, NULL, &shellcode_mem_sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	guard_nts(status, "ZwAllocateVirtualMemory shellcode allocation failed with status: %lx; in proc %s", status, procname)
	log_debug("shellcode allocated @ %p", shellcode_mem);

	SIZE_T protect_sz = 1000;
	ULONG old_page_protection;
	void* protect_addr = entrypoint;
	status = ZwProtectVirtualMemory(hproc, &protect_addr, &protect_sz, PAGE_READWRITE, &old_page_protection);
	guard_nts(status, "ZwProtectVirtualMemory failed setting entrypoint protection to PAGE_READWRITE; "
		"status: %lx; "
		"addr: %p; ",
		status, protect_addr);

	if (a.b == bit::x64) hook64(entrypoint, shellcode_mem);
	else hook32(entrypoint, shellcode_mem);

	status = ZwProtectVirtualMemory(hproc, &protect_addr, &protect_sz, old_page_protection, &old_page_protection);
	guard_nts(status, "ZwProtectVirtualMemory failed restoring entrypoint protection; "
		"status: %lx; "
		"addr: %p; ",
		status, protect_addr);

	protect_addr = shellcode_mem;
	protect_sz = 1000;
	status = ZwProtectVirtualMemory(hproc, &protect_addr, &protect_sz, PAGE_EXECUTE_READ, &old_page_protection);
	guard_nts(status, "ZwProtectVirtualMemory failed setting shellcode protection to PAGE_EXECUTE_READ; "
		"status: %lx; "
		"addr: %p; ",
		status, protect_addr);

	return status;
}

void on_create_proc(HANDLE parent_pid, HANDLE pid, BOOLEAN create) {
	NTSTATUS status = on_create_proc_status(parent_pid, pid, create);
	if (!NT_SUCCESS(status)) log_error("PsSetCreateProcessNotifyRoutine callback failed with status: %lx", status);
}

void on_image_load(PUNICODE_STRING path, HANDLE pid, PIMAGE_INFO info) {
	NTSTATUS status = on_image_load_status(path, pid, info);
	if (!NT_SUCCESS(status)) log_error("PloadImageNotifyRoutine callback failed with status: %lx", status);
}