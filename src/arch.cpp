#include "arch.h"
#include "raii.hpp"

/// figure out the architecture of a peprocess
arch proc_arch(PEPROCESS p) {
	KAPC_STATE state;
	KeStackAttachProcess(p, &state);
	bind_kapc_state(&state);

	arch a;

	#ifdef _WIN64
	if (IoIs32bitProcess(NULL)) {
		a.b = bit::x32;
		a.com = compat::wow;
	}
	else {
		a.b = bit::x64;
		a.com = compat::native;
	}
	#else
	a.b = bit::x32;
	a.com = compat::native;
	#endif

	return a;
}