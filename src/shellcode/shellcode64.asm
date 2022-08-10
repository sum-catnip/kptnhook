bits 64
default rel

%include "src/shellcode/structs.asm" 

; using fastcall convention
; remember shadowspace setup and 16byte alignment before function calls
; stack is misaligned on entry (because of the ret addr)
; RAX, RCX, RDX, R8, R9, R10, R11 are volatile
; RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15 are non-volatile
; but ill restore every register i use because were hooking the entrypoint which wont abide by calling convention rules

; shellcode is using ntdll-only
; this is because it will be injected even into native processes (without kernel32)
; i dont care about those for now so i just exit if k32 is not loaded yet.
; after restoring the original entrypoint ofc.
; to support the native processes aswell you gotta write a native dll to inject and remove my check in here.

; shellcode(original_code*, sz_original_code, dllname*, original_func*)
; original_func* @ rcx
; dllname* @ rdx
; sz_original_code @ r8
; original_code* @ r9

start:

; push parameters as locals
push        r9 ; + 3
push        r8 ; + 2
push        rdx ; + 1
push        rcx ; + 0

; stack frame
push        rbp
lea         rbp, [rsp + ptrsz] ; skip old rbp

; save used non-volatile registers
push        rbx
push        rdi
push        rsi
push        r12

; lets find the ntdll base addr from the teb/peb
; itll be used the whole time so lets store it non-volatile
mov         rbx, gs:[teb.peb]  ; PEB from TEB
test        rbx, rbx
jz          .exit

mov         rbx, [rbx + peb.ldr] ; ldr from peb
test        rbx, rbx
jz          .exit

; linked list is circular so last entry points to first
; we save the fist to check if were done
lea         rcx, [rbx + ldr.modules + listentry.flink] ; &modules
mov         rbx, [rcx + listentry.flink] ; exe image in rbx
cmp         rbx, rcx ; end of list?
je          .exit
mov         rbx, [rbx + listentry.flink] ; ntdll
cmp         rbx, rcx ; end of list?
je          .exit

mov         rbx, [rbx + ldrentry.base - ldrentry.links] ; ntdll base

mov         rcx, sz_vprotect_str
lea         rdx, [vprotect_str]
mov         r8, rbx ; base addr
call        resolve_export
mov         r12, rax

; vprotect to make original entrypoint writable and restore overwritten bytes
mov         rcx, -1 ; current process pseudo-handle
push        qword [rbp] ; original func ptr
mov         rdx, rsp ; original function ptr*
push        qword [rbp + ptrsz * 2] ; original code size
mov         r8, rsp ; original code size*
mov         r9, 4 ; PAGE_READWRITE
push        0 ; space for old protection
push        rsp ; pointer to old protection

; stack is already aligned
; shadow space x32
sub         rsp, 4 * ptrsz
call        r12

add         rsp, 5 * ptrsz ; remove shadow space and old protection ptr
pop         r9 ; pop old protection into new protection
add         rsp, 2 * ptrsz ; pop base addr and region size return values
test        rax, rax
jnz          .exit

mov         rcx, [rbp + ptrsz * 2] ; original code size
mov         rsi, [rbp + ptrsz * 3] ; original code
mov         rdi, [rbp] ; original function

rep         movsb ; memcpy

; restore previous protection
mov         rcx, -1 ; current process pseudo-handle
push        qword [rbp] ; original func ptr
mov         rdx, rsp ; original function ptr*
push        qword [rbp + ptrsz * 2] ; original code size
mov         r8, rsp ; original code size*
; r9 already has the new (old) protection
push        0 ; space for old protection again
push        rsp ; ptr to old protection

; stack is already aligned
; shadow space
sub         rsp, 4 * ptrsz
call        r12
add         rsp, 8 * ptrsz ; remove shadow space, locals and old protection ptr argument

test        rax, rax
jnz          .exit

; check if k32 is loaded
; if not: exit
mov         rdx, gs:[teb.peb]  ; PEB from TEB
test        rdx, rdx
jz          .exit

mov         rdx, [rdx + peb.ldr] ; ldr from peb
test        rdx, rdx
jz          .exit

; linked list is circular so last entry points to first
; we save the fist to check if were done

lea         rcx, [rdx + ldr.modules + listentry.flink] ; &modules
mov         rdx, [rcx + listentry.flink] ; exe image in rdx
cmp         rdx, rcx ; end of list?
je          .exit
mov         rdx, [rdx + listentry.flink] ; ntdll
cmp         rdx, rcx ; end of list?
je          .exit
mov         rdx, [rdx + listentry.flink] ; kernel32
cmp         rdx, rcx ; end of list?
je          .exit

; load library

mov         rcx, sz_load_lib_str
lea         rdx, [load_lib_str]
mov         r8, rbx ; base addr
call        resolve_export

xor         rcx, rcx ; null search path
xor         rdx, rdx ; null characteristics
mov         r8, [rbp + ptrsz * 1] ; dllname
push        0 ; space for return base address
mov         r9, rsp ; return base address*

; shadow space + stack alignment
sub         rsp, 5 * ptrsz
call        rax
add         rsp, 6 * ptrsz ; remove shadow space + alignemnt + base address local

.exit:

pop         r12
pop         rsi
pop         rdi
pop         rbx
pop         rbp

add         rsp, 4 * ptrsz

ret

; resolve_export(sz_name, name*, base*)
; sz_name @ rcx
; name* @ rdx
; base* @ r8
resolve_export:

; getting the name pointer table into r9 (volatile)
mov         r9d, [r8 + dosheader.lfanew] ; rva of pe header
add         r9, r8 ; va of pe header
; get first data directory (export directory)
mov         r9d, [r9 + peheader.optional + optionalheader.dirs]
add         r9, r8 ; export directory va (needed later)

mov         r10d, [r9 + exportdir.addrnames] ; name pointer table rva
add         r10, r8 ; name pointer table va

mov         rax, -1 ; rax as counter
.compare_next_string:
inc         rax

push        rcx ; save name_sz
mov         rdi, rdx ; name
mov         esi, [r10 + rax * 4] ; current name rva
add         rsi, r8 ; current name va

repe        cmpsb ; strcmp
pop         rcx
jne         .compare_next_string

; resolve function addr from the index in rax

mov         r10d, [r9 + exportdir.addrord] ; ordinal table rva
add         r10, r8 ; ordinal table va
mov         ax, [r10 + rax * 2] ; ordinal in ax

mov         r10d, [r9 + exportdir.addrfuncs] ; function address table rva
add         r10, r8 ; function address table va
mov         eax, [r10 + rax * 4] ; rva of function
add         rax, r8 ; va of function

ret

; static data
load_lib_str        db      "LdrLoadDll", 0
sz_load_lib_str     equ     $ - load_lib_str

vprotect_str        db      "NtProtectVirtualMemory", 0
sz_vprotect_str     equ     $ - vprotect_str