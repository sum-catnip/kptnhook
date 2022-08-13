#include "main.h"
#include "log.h"
#include "handler.h"
#include "known_dlls.h"

#include "undocumented.h"
#include "pointers.h"
#include "raii.hpp"

#include <ntimage.h>
#include <ntstrsafe.h>

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path) {
	NTSTATUS status = STATUS_SUCCESS;

	log_debug("driver entry");
	drv->DriverUnload = unload;

	status = PsSetLoadImageNotifyRoutine(on_image_load);
	guard_nts(status, "PsSetLoadImageNotifyRoutine failed with code: 0x%x", status);
	
	status = PsSetCreateProcessNotifyRoutine(on_create_proc, false);
	guard_nts(status, "PsSetLoadImageNotifyRoutine failed with code: 0x%x", status);

	return status;
}

void NTAPI unload(PDRIVER_OBJECT drv) {
	UNREFERENCED_PARAMETER(drv);

	// this only fails if the function was not registered in the first case
	// so im ignoring any errors
	PsSetCreateProcessNotifyRoutine(on_create_proc, true);
	PsRemoveLoadImageNotifyRoutine(on_image_load);

	for (const UNICODE_STRING& filename : KNOWN_DLLS) remove_known_dll(&filename, true);
#ifdef _WIN64
	for (const UNICODE_STRING& filename : KNOWN_DLLS) remove_known_dll(&filename, false);
#endif

	log_debug("driver exiting");
}