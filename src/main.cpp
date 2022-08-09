#include "main.h"
#include "log.h"
#include "handler.h"
#include "known_dlls.h"

#include "undocumented.h"
#include "pointers.h"
#include "raii.hpp"
#include "drvglobal.h"

#include <ntimage.h>
#include <ntstrsafe.h>

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path) {
	NTSTATUS status = STATUS_SUCCESS;

	log_debug("reg path: %wZ", reg_path);

	//RtlUnicodeStringCopy()

	GLOBAL.obj = drv;
	// TODO: ill need to copy the string if i actually need the registry path
	//GLOBAL.registry_path = reg_path;
	log_debug("driver entry");

	drv->DriverUnload = unload;

/*
	log_debug("adding native dlls");
	for (const UNICODE_STRING& filename : KNOWN_DLLS) {
		status = add_known_dll(&filename, true);
		if (! NT_SUCCESS(status)) break;
	}
	guard_nts(status, "error adding native known dlls: %x", status);

	log_debug("adding non-native dlls");
	for (const UNICODE_STRING& filename : KNOWN_DLLS) {
		status = add_known_dll(&filename, false);
		if (! NT_SUCCESS(status)) break;
	}
	guard_nts(status, "error adding non-native known dlls: %x", status);
	*/

	//status = PsSetLoadImageNotifyRoutine(on_image_load);
	status = PsSetLoadImageNotifyRoutine(on_image_load);
	guard_nts(status, "PsSetLoadImageNotifyRoutine failed with code: 0x%x", status);
	
	status = PsSetCreateProcessNotifyRoutine(on_create_proc, false);
	//status = PsSetLoadImageNotifyRoutine(on_image_load);
	guard_nts(status, "PsSetLoadImageNotifyRoutine failed with code: 0x%x", status);

	return status;
}

void NTAPI unload(PDRIVER_OBJECT drv) {
	UNREFERENCED_PARAMETER(drv);

	if (GLOBAL.registry_path) ExFreePool(GLOBAL.registry_path);
	GLOBAL.registry_path = nullptr;

	// this only fails if the function was not registered in the first case
	// so im ignoring any errors
	//PsRemoveLoadImageNotifyRoutine(on_image_load);
	PsSetCreateProcessNotifyRoutine(on_create_proc, true);
	PsRemoveLoadImageNotifyRoutine(on_image_load);

	for (const UNICODE_STRING& filename : KNOWN_DLLS) remove_known_dll(&filename, true);
#ifdef _WIN64
	for (const UNICODE_STRING& filename : KNOWN_DLLS) remove_known_dll(&filename, false);
#endif

	log_debug("driver exiting");
}