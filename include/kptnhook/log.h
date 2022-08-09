#pragma once

#include <ntifs.h>

constexpr auto LOG_LEVEL_DBG   = 4;
constexpr auto LOG_LEVEL_TRACE = 3;
constexpr auto LOG_LEVEL_INFO  = 2;
constexpr auto LOG_LEVEL_WARN  = 1;
constexpr auto LOG_LEVEL_ERR   = 0;

#define log_debug(s, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, LOG_LEVEL_DBG,   "[kptnhook2][debug] " s "\n", __VA_ARGS__)
#define log_trace(s, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, LOG_LEVEL_TRACE, "[kptnhook2][trace] " s "\n", __VA_ARGS__)
#define log_info(s, ...)  DbgPrintEx(DPFLTR_DEFAULT_ID, LOG_LEVEL_INFO,  "[kptnhook2][info]  " s "\n", __VA_ARGS__)
#define log_warn(s, ...)  DbgPrintEx(DPFLTR_DEFAULT_ID, LOG_LEVEL_WARN,  "[kptnhook2][warn]  " s "\n", __VA_ARGS__)
#define log_error(s, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, LOG_LEVEL_ERR,   "[kptnhook2][error] " s "\n", __VA_ARGS__)

#define guard_log(cond, code, msg, ...) if(cond) { log_error(msg, __VA_ARGS__); return code; }
#define guard_nts(status, msg, ...) guard_log(!NT_SUCCESS(status), status, msg, __VA_ARGS__);