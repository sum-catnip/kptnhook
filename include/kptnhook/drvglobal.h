#pragma once

#include <ntifs.h>

struct driverctx {
    PDRIVER_OBJECT obj;
    PUNICODE_STRING registry_path; 
};

extern driverctx GLOBAL;