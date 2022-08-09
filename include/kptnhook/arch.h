#pragma once
#include <ntifs.h>

enum bit { x64, x32 };
enum compat { native, wow };
struct arch {
    bit b;
    compat com;
};

/// figure out the architecture of a peprocess
arch proc_arch(PEPROCESS p);