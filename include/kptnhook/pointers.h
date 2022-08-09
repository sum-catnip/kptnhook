#pragma once

#define addroffset(type, addr, off) reinterpret_cast<type*>(reinterpret_cast<uintptr_t>(addr) + off)
#define addr_relative_to(a1, a2) reinterpret_cast<size_t>(a1) - reinterpret_cast<size_t>(a2)
#define towow64(ptr) static_cast<UINT32>(reinterpret_cast<UINT_PTR>(ptr))