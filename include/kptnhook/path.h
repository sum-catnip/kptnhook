#pragma once
#include <ntifs.h>

bool match_filename(PUNICODE_STRING path, PUNICODE_STRING filename);
bool match_filename_ascii(char* path, char* filename);