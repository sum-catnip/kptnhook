#include "known_dlls.h"
#include "raii.hpp"
#include "log.h"
#include "drvglobal.h"
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

NTSTATUS create_known_dlls(bool native_arch) {
	NTSTATUS status = STATUS_SUCCESS;

	SECURITY_DESCRIPTOR* desc = reinterpret_cast<SECURITY_DESCRIPTOR*>(
		ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR), 'csed'));

	bind_alloc(desc);
	status = RtlCreateSecurityDescriptor(desc, SECURITY_DESCRIPTOR_REVISION);
	guard_nts(status, "RtlCreateSecurityDescriptor failed with: %x", status);
	//desc->Control |= SE_SACL_AUTO_INHERITED;

	SID* sid_admins = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_authnt = SECURITY_NT_AUTHORITY;
	status = alloc_sid(&sid_admins, 'disa', &ident_authnt, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_admins);
	guard_nts(status, "alloc_sid failed with %x", status);

	status = RtlSetOwnerSecurityDescriptor(desc, sid_admins, false);
	guard_nts(status, "RtlSetOwnerSecurityDescriptor(sid_admins) failed with %x", status);

	ULONG dacl_len = sizeof(ACL);

	// create ace sids

	// everyone sid for ace
	SID* sid_everyone = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_world = SECURITY_WORLD_SID_AUTHORITY;
	status = alloc_sid(&sid_everyone, 'dise', &ident_world, { SECURITY_WORLD_RID });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_everyone);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_everyone) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "all application packages" sid for ace
	SID* sid_all_apps = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_apps = SECURITY_APP_PACKAGE_AUTHORITY;
	status = alloc_sid(&sid_all_apps, 'disp', &ident_apps, { SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_all_apps);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_all_apps) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "restricted application packages" sid for ace
	SID* sid_restricted_apps = nullptr;
	status = alloc_sid(
		&sid_restricted_apps,
		'disp',
		&ident_apps,
		{ SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE });

	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_restricted_apps);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_restricted_apps) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "restricted" sid for ace
	SID* sid_restricted = nullptr;
	status = alloc_sid(&sid_restricted, 'disr', &ident_authnt, { SECURITY_RESTRICTED_CODE_RID });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_restricted);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_restricted) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "administrator" sid for ace
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_admins) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	ACL* dacl = reinterpret_cast<ACL*>(ExAllocatePoolWithTag(PagedPool, dacl_len, 'lcad'));
	if (! dacl) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(dacl);

	status = RtlCreateAcl(dacl, dacl_len, ACL_REVISION);
	guard_nts(status, "RtlCreateAcl(dacl) failed with %x", status);

	ACCESS_MASK mask_section_rw = SECTION_QUERY | SECTION_MAP_WRITE;

	// access allowed administrators ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, sid_admins);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed everyone ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rw, sid_everyone);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed all application packages ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rw, sid_all_apps);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed restricted application packages ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rw, sid_restricted_apps);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed restricted ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rw, sid_restricted);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	ULONG sacl_len = sizeof(ACL);

	// "trust label" sid for ace
	SID* sid_trust_label = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_trust = SECURITY_PROCESS_TRUST_AUTHORITY;
	status = alloc_sid(
		&sid_trust_label,
		'dist',
		&ident_trust,
		{ SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID, SECURITY_PROCESS_PROTECTION_LEVEL_WINTCB_RID });

	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_trust_label);
	guard_nts(status, "alloc_sid failed with %x", status);
	ULONG ace_trust_len = 
		sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE)
		+ RtlLengthSid(sid_trust_label)
		- sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE::SidStart);
	sacl_len += ace_trust_len;

	ACL* sacl = reinterpret_cast<ACL*>(ExAllocatePoolWithTag(PagedPool, sacl_len, 'lcas'));
	if (! sacl) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(sacl);

	status = RtlCreateAcl(sacl, sacl_len, ACL_REVISION);
	guard_nts(status, "RtlCreateAcl(sacl) failed with %x", status);

	// allocate trust label ace
	SYSTEM_PROCESS_TRUST_LABEL_ACE* ace_trust = reinterpret_cast<SYSTEM_PROCESS_TRUST_LABEL_ACE*>(
		ExAllocatePoolWithTag(PagedPool, ace_trust_len, 'ecat'));

	if (! ace_trust) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(ace_trust);

	// initialize ace
	memset(ace_trust, 0, ace_trust_len);
	ace_trust->Header.AceSize = ace_trust_len;
	ace_trust->Header.AceType = SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE;
	ace_trust->Mask = READ_CONTROL | mask_section_rw;
	// [GlobalInject][error] ZwCreateSection(agent) failed with: c0000022
	status = RtlCopySid(
			ace_trust_len
			- sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE)
			+ sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE::SidStart),
		reinterpret_cast<PSID>(&ace_trust->SidStart),
		sid_trust_label);

	guard_nts(status, "RtlCopySid(trust_level_sid) failed with %x", status);

	// add ace
	status = RtlAddAce(sacl, ACL_REVISION, MAXULONG, ace_trust, ace_trust_len);
	guard_nts(status, "RtlAddAce(sacl, trust_label_ace) failed with %x", status);

	status = RtlSetDaclSecurityDescriptor(desc, true, dacl, false);
	guard_nts(status, "RtlSetDaclSecurityDescriptor failed with %x", status);

	status = RtlSetSaclSecurityDescriptor(desc, true, sacl, false);
	guard_nts(status, "RtlSetSaclSecurityDescriptor failed with %x", status);

	if (! RtlValidSecurityDescriptor(desc)) {
		log_error("invalid security descriptor for agent section");
		return STATUS_INVALID_SECURITY_DESCR;
	}

	// initialize attributes for agent knowndll object
	OBJECT_ATTRIBUTES known_dlls_attr;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING obj_path_known_dlls;
		if (native_arch) obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls_2\\");
		else             obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls32_2\\");

		InitializeObjectAttributes(&known_dlls_attr, &obj_path_known_dlls, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, desc);
	}

	// TODO: if this doesn't work, let's make a new onimageload hook only for knowndll initializing
	// should've done this in the first place lol

	HANDLE known_dlls_hwnd;
	status = ZwCreateDirectoryObject(&known_dlls_hwnd, DIRECTORY_CREATE_OBJECT, &known_dlls_attr);
	guard_nts(status, "error creating knowndlls directory: %x", status);

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

	//status = ObReferenceObjectByHandleWithTag(handle_section_agent, 0, NULL, KernelMode, 'esga', section, NULL);
	//guard_nts(status, "ObReferenceObjectByHandleWithTag(handle_section_agent) failed with: %x", status);

	return status;
}

/// <summary>
/// adds a knowndll to the obj storage
/// </summary>
/// <returns></returns>
/*
NTSTATUS add_known_dll(const UNICODE_STRING* filename, bool native_arch) {
	NTSTATUS status = STATUS_SUCCESS;
	log_debug("adding known dll %wZ | is_native: %d", filename, native_arch);

	status = create_known_dlls(native_arch);
	guard_nts(status, "error creating knowndlls: %x", status);

	bool exists;
	status = known_dll_exists(filename, native_arch, &exists);
	guard_nts(status, "failed checking if known dll already exists while adding it", status);
	if (exists) return status;

	// escalate to system process
	KAPC_STATE state;
	KeStackAttachProcess(PsInitialSystemProcess, &state);
	bind_kapc_state(&state);
	log_debug("attached to system process");

	// initialize empty security descriptor

	SECURITY_DESCRIPTOR* desc = reinterpret_cast<SECURITY_DESCRIPTOR*>(
		ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR), 'csed'));
	bind_alloc(desc);
	status = RtlCreateSecurityDescriptor(desc, SECURITY_DESCRIPTOR_REVISION);
	guard_nts(status, "RtlCreateSecurityDescriptor failed with: %x", status);
	//desc->Control |= SE_SACL_AUTO_INHERITED;

	SID* sid_admins = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_authnt = SECURITY_NT_AUTHORITY;
	status = alloc_sid(&sid_admins, 'disa', &ident_authnt, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_admins);
	guard_nts(status, "alloc_sid failed with %x", status);

	status = RtlSetOwnerSecurityDescriptor(desc, sid_admins, false);
	guard_nts(status, "RtlSetOwnerSecurityDescriptor(sid_admins) failed with %x", status);

	ULONG dacl_len = sizeof(ACL);

	// create ace sids

	// everyone sid for ace
	SID* sid_everyone = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_world = SECURITY_WORLD_SID_AUTHORITY;
	status = alloc_sid(&sid_everyone, 'dise', &ident_world, { SECURITY_WORLD_RID });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_everyone);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_everyone) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "all application packages" sid for ace
	SID* sid_all_apps = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_apps = SECURITY_APP_PACKAGE_AUTHORITY;
	status = alloc_sid(&sid_all_apps, 'disp', &ident_apps, { SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_all_apps);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_all_apps) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "restricted application packages" sid for ace
	SID* sid_restricted_apps = nullptr;
	status = alloc_sid(
		&sid_restricted_apps,
		'disp',
		&ident_apps,
		{ SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE });

	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_restricted_apps);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_restricted_apps) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "restricted" sid for ace
	SID* sid_restricted = nullptr;
	status = alloc_sid(&sid_restricted, 'disr', &ident_authnt, { SECURITY_RESTRICTED_CODE_RID });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_restricted);
	guard_nts(status, "alloc_sid failed with %x", status);
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_restricted) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	// "administrator" sid for ace
	dacl_len += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid_admins) - sizeof(ACCESS_ALLOWED_ACE::SidStart);

	ACL* dacl = reinterpret_cast<ACL*>(ExAllocatePoolWithTag(PagedPool, dacl_len, 'lcad'));
	if (! dacl) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(dacl);

	status = RtlCreateAcl(dacl, dacl_len, ACL_REVISION);
	guard_nts(status, "RtlCreateAcl(dacl) failed with %x", status);

	ACCESS_MASK mask_section_rwx = SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;

	// access allowed everyone ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rwx, sid_everyone);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed all application packages ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rwx, sid_all_apps);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed restricted application packages ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rwx, sid_restricted_apps);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed restricted ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, READ_CONTROL | mask_section_rwx, sid_restricted);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	// access allowed administrators ace
	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, STANDARD_RIGHTS_REQUIRED | mask_section_rwx | SECTION_EXTEND_SIZE, sid_admins);
	guard_nts(status, "RtlAddAccessAllowedAce(sid_everyone) failed with %x", status);

	ULONG sacl_len = sizeof(ACL);

	// "low manditory label" sid for ace
	SID* sid_low_manditory = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_manditory = SECURITY_MANDATORY_LABEL_AUTHORITY;
	status = alloc_sid(&sid_low_manditory, 'dism', &ident_manditory, { SECURITY_MANDATORY_LOW_RID });
	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_low_manditory);
	guard_nts(status, "alloc_sid failed with %x", status);
	ULONG ace_manditory_len =
		sizeof(SYSTEM_MANDATORY_LABEL_ACE)
		+ RtlLengthSid(sid_low_manditory)
		- sizeof(SYSTEM_MANDATORY_LABEL_ACE::SidStart);
	sacl_len += ace_manditory_len;

	// "trust label" sid for ace
	SID* sid_trust_label = nullptr;
	SID_IDENTIFIER_AUTHORITY ident_trust = SECURITY_PROCESS_TRUST_AUTHORITY;
	status = alloc_sid(
		&sid_trust_label,
		'dist',
		&ident_trust,
		{ SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID, SECURITY_PROCESS_PROTECTION_LEVEL_WINTCB_RID });

	// alloc_res should protect us from a double free here but im just gonna make sure
	if(status == STATUS_MEMORY_NOT_ALLOCATED) return status;
	bind_alloc(sid_trust_label);
	guard_nts(status, "alloc_sid failed with %x", status);
	ULONG ace_trust_len = 
		sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE)
		+ RtlLengthSid(sid_trust_label)
		- sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE::SidStart);
	sacl_len += ace_trust_len;

	ACL* sacl = reinterpret_cast<ACL*>(ExAllocatePoolWithTag(PagedPool, sacl_len, 'lcas'));
	if (! sacl) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(sacl);

	status = RtlCreateAcl(sacl, sacl_len, ACL_REVISION);
	guard_nts(status, "RtlCreateAcl(sacl) failed with %x", status);

	// create and add aces to the sacl

	// allocate manditory ace
	SYSTEM_MANDATORY_LABEL_ACE* ace_manditory = reinterpret_cast<SYSTEM_MANDATORY_LABEL_ACE*>(
		ExAllocatePoolWithTag(PagedPool, ace_manditory_len, 'ecam'));
	if (! ace_manditory) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(ace_manditory);

	// initialize ace
	memset(ace_manditory, 0, ace_manditory_len);
	ace_manditory->Header.AceSize = ace_manditory_len;
	ace_manditory->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
	ace_manditory->Mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
	status = RtlCopySid(
			ace_manditory_len
			- sizeof(SYSTEM_MANDATORY_LABEL_ACE)
			+ sizeof(SYSTEM_MANDATORY_LABEL_ACE::SidStart),
		reinterpret_cast<PSID>(&ace_manditory->SidStart),
		sid_low_manditory);

	guard_nts(status, "RtlCopySid(low_mandatory_level_sid) failed with %x", status);

	// add ace
	status = RtlAddAce(sacl, ACL_REVISION, MAXULONG, ace_manditory, ace_manditory_len);
	guard_nts(status, "RtlAddAce(sacl, mandatory_label_ace) failed with %x", status);

	// allocate trust label ace
	SYSTEM_PROCESS_TRUST_LABEL_ACE* ace_trust = reinterpret_cast<SYSTEM_PROCESS_TRUST_LABEL_ACE*>(
		ExAllocatePoolWithTag(PagedPool, ace_trust_len, 'ecat'));

	if (! ace_trust) return STATUS_MEMORY_NOT_ALLOCATED;
	bind_alloc(ace_trust);

	// initialize ace
	memset(ace_trust, 0, ace_trust_len);
	ace_trust->Header.AceSize = ace_trust_len;
	ace_trust->Header.AceType = SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE;
	ace_trust->Mask = READ_CONTROL | mask_section_rwx;
	// [GlobalInject][error] ZwCreateSection(agent) failed with: c0000022
	status = RtlCopySid(
			ace_trust_len
			- sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE)
			+ sizeof(SYSTEM_PROCESS_TRUST_LABEL_ACE::SidStart),
		reinterpret_cast<PSID>(&ace_trust->SidStart),
		sid_trust_label);

	guard_nts(status, "RtlCopySid(trust_level_sid) failed with %x", status);

	// add ace
	status = RtlAddAce(sacl, ACL_REVISION, MAXULONG, ace_trust, ace_trust_len);
	guard_nts(status, "RtlAddAce(sacl, trust_label_ace) failed with %x", status);

	status = RtlSetDaclSecurityDescriptor(desc, true, dacl, false);
	guard_nts(status, "RtlSetDaclSecurityDescriptor failed with %x", status);

	status = RtlSetSaclSecurityDescriptor(desc, true, sacl, false);
	guard_nts(status, "RtlSetSaclSecurityDescriptor failed with %x", status);

	if (! RtlValidSecurityDescriptor(desc)) {
		log_error("invalid security descriptor for agent section");
		return STATUS_INVALID_SECURITY_DESCR;
	}

	// initialize attributes for agent knowndll object
	OBJECT_ATTRIBUTES obj_attr_agent;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING obj_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING obj_path_known_dlls;
		if (native_arch) obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls\\");
		else             obj_path_known_dlls = RTL_CONSTANT_STRING(L"\\KnownDlls32\\");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, &obj_path_known_dlls);
		guard_nts(status, "knowndlls path exceeds max path length");
		status = RtlAppendUnicodeStringToString(&obj_path_agent, filename);
		guard_nts(status, "agent filename exceeds max path length");

		InitializeObjectAttributes(&obj_attr_agent, &obj_path_agent, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, desc);
	}

	// initialize attributes for agent disk image
	OBJECT_ATTRIBUTES disk_attr_agent;
	{
		wchar_t pathbuf[MAX_PATH] = { 0 };
		UNICODE_STRING disk_path_agent = { 0, sizeof(pathbuf), pathbuf };
		UNICODE_STRING disk_path_system;
		if (native_arch) disk_path_system = RTL_CONSTANT_STRING(L"\\systemroot\\system32\\");
		else             disk_path_system = RTL_CONSTANT_STRING(L"\\systemroot\\syswow64\\");
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

	guard_nts(status, "ZwOpenFile(agent) failed with: %x ; native: %d", status, native_arch);
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

	guard_nts(status, "ZwCreateSection(agent) failed with: %x ; native: %d", status, native_arch);
	bind_handle(handle_section_agent);

	//status = ObReferenceObjectByHandleWithTag(handle_section_agent, 0, NULL, KernelMode, 'esga', section, NULL);
	//guard_nts(status, "ObReferenceObjectByHandleWithTag(handle_section_agent) failed with: %x", status);

	return status;
}
*/