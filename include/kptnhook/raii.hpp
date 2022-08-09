#pragma once
#include <ntifs.h>

#define _CONCAT(x,y) x ## y
#define CONCAT(x,y) _CONCAT(x,y)

template<class T>
class raiiwrap {
public:
	raiiwrap(T inner) : m_inner(inner) {}
protected:
	T m_inner;
};

#define bind_peprocess(p) auto CONCAT(anonymous, __LINE__) = peprocess_res(p);
class peprocess_res : public raiiwrap<PEPROCESS> {
public:
	peprocess_res(PEPROCESS p) : raiiwrap(p) {};
	~peprocess_res() { ObDereferenceObject(m_inner); }
};

#define bind_handle(h) auto CONCAT(anonymous, __LINE__) = handle_res(h);
class handle_res : public raiiwrap<HANDLE> {
public: 
	handle_res(HANDLE p) : raiiwrap(p) {};
	~handle_res() { ZwClose(m_inner); }
};

#define bind_kapc_state(p) auto CONCAT(anonymous, __LINE__) = kapc_state_res(p);
class kapc_state_res : public raiiwrap<PKAPC_STATE> {
public:
	kapc_state_res(PKAPC_STATE p) : raiiwrap(p) {};
	~kapc_state_res() { KeUnstackDetachProcess(m_inner); }
};

#define bind_alloc(p) auto CONCAT(anonymous, __LINE__) = alloc_res(p);
class alloc_res : public raiiwrap<PVOID> {
public:
	alloc_res(PVOID p) : raiiwrap(p) {};
	~alloc_res() { if(m_inner) ExFreePool(m_inner); }
};
