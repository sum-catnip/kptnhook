bits 32
default rel

%include "src/shellcode/structs.asm" 

; TODO:
; dll is not loaded?
; loadlibrary says dll not found??
; dll seems to not be in knowndlls
; init lazy is not called??

; calling convention (stdcall'ish TM):
; callee cleans up stack params
; params pushed in order
; eax, ecx and edx are volatile

; shellcode(original_code*, sz_original_code, dllname*, sz_dllname, original_func*)
; stack layout:
;   original_func*
;   sz_dllname
;   dllname*
;   sz_original_code
;   original_code*
start:
push        ebp
mov         ebp, esp ; frame pointer points to start of args
add         ebp, ptrsz
pushad ; we dont know what the target exe might expect from the windows loader environment
; so just save the entire environment

; traverse the teb/peb to get the kernel32 base address

mov         ebx, fs:[teb.peb]  ; PEB from TEB
mov         ebx, [ebx + peb.ldr] ; LDR from PEB
; the address of the pointer to the first entry
; last entry will point to this so we can check if the list is exhausted
lea         ecx, [ebx + ldr.modules + listentry.flink] ; addressof modules pointer
mov         ebx, [ecx] ; first entry is the exe image itself
mov         ebx, [ebx + listentry.flink] ; next entry is ntdll
cmp         ebx, ecx ; found end of list?
je          .exit
; mov         ebx, [ebx + listentry.flink] ; and now kernel32
; cmp         ebx, ecx ; end of list?
; je          .exit

; difference between dllbase field and flink (where we land)
; so ebx now holds the ntdll base address
mov         ebx, [ebx + ldrentry.base - ldrentry.links]

; eip relative access on x86-32asm
call        .push_ip_vprotect
.push_ip_vprotect:
add         dword [esp], vprotect_str - $
push        sz_vprotect_str
push        ebx
call        resolve_export

push        eax ; save virtualprotect addr for second call

; save original func ptr (modified in vprotect call)
push        dword [ebp]
; save original code size
push        dword [ebp + ptrsz * 3]

; make original func writable
push        0 ; space for old protect
push        esp ; old protect ptr
push        4 ; PAGE_READWRITE
lea         edx, [ebp + ptrsz * 3] ; original code size * 
push        edx
push        ebp ; original func *
push        -1 ; current process pseudo-handle
call        eax

test        eax, eax
pop         edx ; old protect
; restore original code size
pop         eax
mov         dword [ebp + ptrsz * 3], eax
; restore original func ptr
pop         eax
mov         dword [ebp], eax
pop         eax ; saved virtual protect addr

jnz          .exit

; restore original code (memcpy)
mov         ecx, [ebp + ptrsz * 3] ; original code size (param)
mov         esi, [ebp + ptrsz * 4] ; original code (param)
mov         edi, [ebp] ; original func

rep         movsb ; memcpy

; restore previous protection

; save original func ptr (modified in vprotect call)
push        dword [ebp]
; save original code size
push        dword [ebp + ptrsz * 3]

push        0 ; space for old protect
push        esp ; old protect ptr
push        edx ; new protect (previous value)
lea         edx, [ebp + ptrsz * 3] ; original code size * 
push        edx
push        ebp ; original func *
push        -1 ; current process pseudo-handle
call        eax

add         esp, ptrsz ; remove old page protection

test        eax, eax

; restore original code size
pop         eax
mov         dword [ebp + ptrsz * 3], eax
; restore original func ptr
pop         eax
mov         dword [ebp], eax

jnz          .exit

; check if k32 is loaded
; if not: exit
mov         edx, fs:[teb.peb]  ; PEB from TEB
mov         edx, [edx + peb.ldr] ; LDR from PEB
; the address of the pointer to the first entry
; last entry will point to this so we can check if the list is exhausted
lea         ecx, [edx + ldr.modules + listentry.flink] ; addressof modules pointer
mov         edx, [ecx] ; first entry is the exe image itself
mov         edx, [edx + listentry.flink] ; next entry is ntdll
cmp         edx, ecx ; found end of list?
je          .exit
mov         edx, [edx + listentry.flink] ; and now kernel32
cmp         edx, ecx ; end of list?
je          .exit

; load library

call        .push_ip_load_lib
.push_ip_load_lib:
add         dword [esp], load_lib_str - $

push        sz_load_lib_str

push        ebx
call        resolve_export

mov         ecx, [ebp + ptrsz * 2]
push        0
push        esp ; return base address
push        ecx ; dllname
push        0 ; characteristics
push        0 ; search path
call        eax ; loadlibrarya

pop         eax ; dump return base addr

.exit:
popad
pop         ebp
ret         4 * ptrsz

; resolve_export(name*, sz_name, base*)
; stack layout:
;   return*
;   base*
;   sz_name
;   name*
resolve_export:
push        esp
push        ebp
push        ebx
push        esi
push        edi

; skip saved registers and return addr
; esp now points to the start of the parameters
add         esp, ptrsz * 6

; parse kernel32s pe header and find the export tables
mov         ebp, [esp] ; module base in ebp
mov         ebx, [ebp + dosheader.lfanew] ; rva pe header in ebx
add         ebx, ebp ; va of pe header
; export directory is the first data directory
mov         ebx, [ebx + peheader.optional + optionalheader.dirs]
add         ebx, ebp ; export directory rva to va

mov         edx, [ebx + exportdir.addrnames] ; edx = address of names rva
add         edx, ebp ; address of names va

mov         eax, -1 ; eax as counter
.compare_next_string:
inc         eax

mov         ecx, [esp + ptrsz] ; sz_name
mov         edi, [esp + ptrsz * 2]
mov         esi, [edx + eax * 4] ; current name rva in esi
add         esi, ebp ; name va in esi

repe        cmpsb ; compare strings
jne         .compare_next_string

mov         edx, [ebx + exportdir.addrord] ; edx = address of ordinals rva
add         edx, ebp ; address of ordinals va
mov         ax, [edx + eax * 2] ; ordinal in ax

mov         edx, [ebx + exportdir.addrfuncs] ; ebx = address of funcs rva
add         edx, ebp ; address of funcs va
mov         eax, [edx + eax * 4] ; rva of function
add         eax, ebp

sub         esp, ptrsz * 6

pop         edi
pop         esi
pop         ebx
pop         ebp
pop         esp
ret         3 * ptrsz ; cleanup arguments

; static data "segment"
load_lib_str        db      "LdrLoadDll", 0
sz_load_lib_str     equ     $ - load_lib_str

vprotect_str        db      "NtProtectVirtualMemory", 0
sz_vprotect_str     equ     $ - vprotect_str