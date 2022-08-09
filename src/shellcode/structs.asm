%if __BITS__ = 64
    %define resp resq
    %define ptrsz 8
%endif

%if __BITS__ = 32
    %define resp resd
    %define ptrsz 4
%endif

struc teb
    .reserved1   resp    12
    .peb         resp    1
    .reserved2   resp    399
    .reserved3   resb    1952
    .tlsslots    resp    64
    .reserved4   resb    8
    .reserved5   resp    26
    .ole         resp    1
    .reserved6   resp    4
    .tlsexpand   resp    1
endstruc

struc peb
    .reserved1   resb   2
    .debugged    resb   1
    .reserved2   resb   1
    %if __BITS__ = 64
        .padding    resb    4
    %endif
    .reserved3   resp   2
    .ldr         resp   1
    .params      resp   1
    .reserved4   resp   3
    .atl         resp   1
    .reserved5   resp   1
    .reserved6   resd   1
    .reserved7   resp   1
    .reserved8   resd   1
    .atl32       resd   1
    .reserved9   resp   45
    .reserved10  resb   96
    .ppi         resp   1
    .reserved11  resb   128
    .reserved12  resp   1
    .sid         resd   1
endstruc

struc listentry
    .flink       resp   1
    .blink       resp   1
endstruc

struc ldr
    .reserved1   resb   8
    .reserved2   resp   3
    .modules     resb   listentry_size
endstruc

struc unicode_string
    .len         resw   1
    .maxlen      resw   1
    .buffer      resp   1
endstruc

struc ldrentry
    .reserved1   resp   2
    .links       resb   listentry_size
    .reserved2   resp   2
    .base        resp   1
    .entrypoint  resp   1
    .reserved3   resp   1
    .fullname    resb   unicode_string_size
    .reserved4   resb   8
    .reserved5   resp   3
    .reserved6   resp   1
    .datetime    resd   1
endstruc

struc dosheader
    .magic       resw   1
    .cblp        resw   1
    .cp          resw   1
    .crlc        resw   1
    .cparhdr     resw   1
    .minalloc    resw   1
    .maxalloc    resw   1
    .ss          resw   1
    .sp          resw   1
    .csum        resw   1
    .ip          resw   1
    .cs          resw   1
    .lfarlc      resw   1
    .ovno        resw   1
    .res         resw   4
    .oemid       resw   1
    .oeminfo     resw   1
    .res2        resw   10
    .lfanew      resd   1
endstruc

struc fileheader
    .machine     resw   1
    .numsections resw   1
    .datetime    resd   1
    .symbols     resd   1
    .numsymbols  resd   1
    .szoptional  resw   1
    .char        resw   1
endstruc

struc datadirectory
    .va          resd   1
    .size        resd   1
endstruc

struc optionalheader
    .magic       resw   1
    .lnkmajor    resb   1
    .lnkminor    resb   1
    .szcode      resd   1
    .szinit      resd   1
    .szuninit    resd   1
    .entrypoint  resd   1
    .base_code   resd   1
    %if __BITS__ = 32
        .base_data   resd   1
    %endif
    .imgbase     resp   1
    .sec_align   resd   1
    .file_align  resd   1
    .osmajor     resw   1
    .osminor     resw   1
    .imgmajor    resw   1
    .imgminor    resw   1
    .submajor    resw   1
    .subminor    resw   1
    .w32ver      resd   1
    .szimg       resd   1
    .szheaders   resd   1
    .checksum    resd   1
    .subsystem   resw   1
    .dllchar     resw   1
    .szstackres  resp   1
    .szstackcom  resp   1
    .szheapres   resp   1
    .szheapcom   resp   1
    .ldrflags    resd   1
    .numrva      resd   1
    .dirs        resb   datadirectory_size * 16
endstruc

struc peheader
    .signature   resd   1
    .file        resb   fileheader_size
    .optional    resb   optionalheader_size
endstruc

struc exportdir
    .char        resd   1
    .datetime    resd   1
    .vermajor    resw   1
    .verminor    resw   1
    .name        resd   1
    .base        resd   1
    .numfuncs    resd   1
    .numnames    resd   1
    .addrfuncs   resd   1
    .addrnames   resd   1
    .addrord     resd   1
endstruc