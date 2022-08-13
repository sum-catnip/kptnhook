#include "known_dlls.h"
#include "raii.hpp"
#include "log.h"
#include "undocumented.h"

#include <minwindef.h>

constexpr auto SEC_IMAGE = 0x01000000;

NTSTATUS known_dll_exists(const UNICODE_STRING* filename, bool native_arch, bool* exists) {
	NTSTATUS status = STATUS_SUCCESS;

	// initialize attributes for agent knowndll object
	OBJECT_ATTRIBUTES obj_attr;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING obj_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING obj_path_known_dlls;
		if (native_arch) obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls\\");
		else             obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls32\\");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, &obj_path_known_dlls);
		guard_nts(status, "knowndlls path exceeds max path length: %d", obj_path_agent.MaximumLength);
		status = RtlAppendUnicodeStringToString(&obj_path_agent, filename);
		guard_nts(status, "agent filename exceeds max path length");

		InitializeObjectAttributes(&obj_attr, &obj_path_agent, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
	}

	HANDLE obj_handle;
	status = ZwOpenSection(&obj_handle, SECTION_MAP_EXECUTE | SECTION_QUERY, &obj_attr);
	if(status == STATUS_OBJECT_NAME_NOT_FOUND) {
		*exists = false;
		status = STATUS_SUCCESS;
	} else { *exists = true; }
	guard_nts(status, "ZwOpenSection(agent) failed with: %x", status);
	bind_handle(obj_handle);

	return status;
}

NTSTATUS remove_known_dll(const UNICODE_STRING* filename, bool native_arch) {
	NTSTATUS status = STATUS_SUCCESS;
	bool exists;
	status = known_dll_exists(filename, native_arch, &exists);
	guard_nts(status, "failed checking if known dll already exists while removing it", status);
	if (! exists) return status;

	// initialize attributes for agent knowndll object
	OBJECT_ATTRIBUTES obj_attr;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING obj_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING obj_path_known_dlls;
		if (native_arch) obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls\\");
		else             obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls32\\");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, &obj_path_known_dlls);
		guard_nts(status, "knowndlls path exceeds max path length: %d", obj_path_agent.MaximumLength);
		status = RtlAppendUnicodeStringToString(&obj_path_agent, filename);
		guard_nts(status, "agent filename exceeds max path length");

		InitializeObjectAttributes(&obj_attr, &obj_path_agent, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
	}

	HANDLE obj_handle;
	status = ZwOpenSection(&obj_handle, SECTION_MAP_EXECUTE | SECTION_QUERY, &obj_attr);
	guard_nts(status, "ZwOpenSection(agent) failed with: %x", status);
	bind_handle(obj_handle);

	ZwMakeTemporaryObject(obj_handle);

	return status;
}

template <int N>
NTSTATUS alloc_sid(SID** sid, ULONG tag, PSID_IDENTIFIER_AUTHORITY auth_id, const ULONG (&subauthorities)[N]) {
	NTSTATUS status = STATUS_SUCCESS;

	// allocate sid (dynamic array)
	// prolly allocates an extra ULONG but better safe than sorry
	*sid = reinterpret_cast<SID*>(ExAllocatePoolWithTag(PagedPool, sizeof(SID) + sizeof(subauthorities), tag));
	if (! *sid) return STATUS_MEMORY_NOT_ALLOCATED;

	// initialize sid
	status = RtlInitializeSid(*sid, auth_id, sizeof(subauthorities) / sizeof(subauthorities[0]));
	guard_nts(status, "RtlInitializeSid failed with %x", status);

	// copy each subauthority
	for(size_t i = 0; i < sizeof(subauthorities) / sizeof(subauthorities[0]); i++) {
		PULONG subauth = RtlSubAuthoritySid(*sid, i);
		if (! subauth) return STATUS_INVALID_SID;
		*subauth = subauthorities[i];
	}

	if (! RtlValidSid(*sid)) {
		log_error("created invalid security descrriptor");
		return STATUS_INVALID_SID;
	}

	return status;
}

/// <summary>
/// adds a knowndll to the obj storage
/// </summary>
/// <returns></returns>
NTSTATUS add_known_dll(const UNICODE_STRING* filename, arch a) {
	NTSTATUS status = STATUS_SUCCESS;
	log_debug("adding known dll %wZ", filename);

	// attach to wintcb signed system process
	KAPC_STATE state;
	KeStackAttachProcess(PsInitialSystemProcess, &state);
	bind_kapc_state(&state);

	// object attributes for kernel32 section
	// were gonna copy the kernel32 security descriptor
	// first i made my own but trust me this is much more stable
	OBJECT_ATTRIBUTES obj_attr_k32;
	{
		UNICODE_STRING obj_path_k32;
		if (a.com == compat::native) obj_path_k32 = RTL_CONSTANT_STRING(L"\\KnownDlls\\kernel32.dll");
		else                         obj_path_k32 = RTL_CONSTANT_STRING(L"\\KnownDlls32\\kernel32.dll");

		InitializeObjectAttributes(&obj_attr_k32, &obj_path_k32, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
	}

	HANDLE hk32;
	status = ZwOpenSection(&hk32, READ_CONTROL, &obj_attr_k32);
	guard_nts(status, "failed to open k32 section obj handle: %x", status);

	ULONG sd_size = 0;
	SECURITY_INFORMATION sd_info =
		PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION |
		LABEL_SECURITY_INFORMATION |
		OWNER_SECURITY_INFORMATION;

	status = ZwQuerySecurityObject(hk32, sd_info, nullptr, sd_size, &sd_size);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		log_error("getting k32 sd size failed with: %x", status);
		return status;
	}

	SECURITY_DESCRIPTOR* k32_sd = reinterpret_cast<SECURITY_DESCRIPTOR*>(
		ExAllocatePoolWithTag(PagedPool, sd_size, 'd23k'));
	bind_alloc(k32_sd);

	status = ZwQuerySecurityObject(hk32, sd_info, k32_sd, sd_size, &sd_size);
	guard_nts(status, "getting k32 sd failed with: %x", status);
	if (! RtlValidSecurityDescriptor(k32_sd)) {
		log_error("invalid k32 security descriptor");
		return STATUS_INVALID_SECURITY_DESCR;
	}

	// initialize attributes for agent knowndll object
	OBJECT_ATTRIBUTES obj_attr_agent;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING obj_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING obj_path_known;
		if (a.com == compat::native) obj_path_known = RTL_CONSTANT_STRING(L"\\KnownDlls\\");
		else                         obj_path_known = RTL_CONSTANT_STRING(L"\\KnownDlls32\\");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, &obj_path_known);
		guard_nts(status, "knowndlls path exceeds max path length");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, filename);
		guard_nts(status, "agent filename exceeds max path length");

		InitializeObjectAttributes(&obj_attr_agent, &obj_path_agent, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, k32_sd);
	}

	// initialize attributes for agent disk image
	OBJECT_ATTRIBUTES disk_attr_agent;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING disk_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING disk_path_system;
		if (a.com == compat::native) disk_path_system = RTL_CONSTANT_STRING(L"\\systemroot\\system32\\");
		else             	         disk_path_system = RTL_CONSTANT_STRING(L"\\systemroot\\syswow64\\");
		status = RtlAppendUnicodeStringToString(&disk_path_agent, &disk_path_system);
		guard_nts(status, "system path exceeds max path length");
		status = RtlAppendUnicodeStringToString(&disk_path_agent, filename);
		guard_nts(status, "agent filename exceeds max path length");

		InitializeObjectAttributes(&disk_attr_agent, &disk_path_agent, OBJ_CASE_INSENSITIVE, NULL, NULL);
	}

	HANDLE disk_handle_agent;
	IO_STATUS_BLOCK disk_iosb_agent;

	// create agent.dll knowndlls segment

	status = ZwOpenFile(
		&disk_handle_agent,
		FILE_GENERIC_READ | FILE_EXECUTE,
		&disk_attr_agent,
		&disk_iosb_agent,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT);

	guard_nts(status, "ZwOpenFile(agent) failed with: %x", status);
	bind_handle(disk_handle_agent);

	HANDLE handle_section_agent;
	status = ZwCreateSection(
		&handle_section_agent,
		SECTION_MAP_EXECUTE | SECTION_QUERY,
		&obj_attr_agent,
		0,
		PAGE_EXECUTE,
		SEC_IMAGE,
		disk_handle_agent);

	guard_nts(status, "ZwCreateSection(agent) failed with: %x", status);
	bind_handle(handle_section_agent);

	return status;
}