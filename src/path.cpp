#include "path.h"

/// <summary>
/// checks if the filename segment of a filepath matches a given filename
/// </summary>
/// <param name="path"></param>
/// <param name="filename"></param>
/// <returns></returns>
bool match_filename(PUNICODE_STRING path, PUNICODE_STRING filename) {
	auto path_end = path->Buffer + (path->Length / sizeof(WCHAR));
	auto fn_end = filename->Buffer + (filename->Length / sizeof(WCHAR));

	auto path_curr = path_end;
	auto fn_curr = fn_end;

	while (path_curr != path->Buffer && fn_curr != filename->Buffer && *path_curr != L'\\') {
		if (towlower(*(fn_curr--)) != towlower(*(path_curr--))) return false;
	}

	return fn_curr == filename->Buffer;
}

bool match_filename_ascii(char* path, char* filename) {
	auto path_end = path + strlen(path);
	auto fn_end = filename + strlen(filename);

	auto path_curr = path_end;
	auto fn_curr = fn_end;

	while (path_curr != path && fn_curr != filename && *path_curr != '\\') {
		if (tolower(*(fn_curr--)) != tolower(*(path_curr--))) return false;
	}

	return fn_curr == filename;
}