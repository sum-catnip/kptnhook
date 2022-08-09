<#
    compiles an asm file into a c-style byte array
#>
param (
    # path to asm file
    [parameter(mandatory=$true)]
    [string]$path
)

$nasm = "$env:LOCALAPPDATA\bin\NASM\nasm.exe"

if (-not (test-path $nasm)) {
    write-error "nasm.exe not found in appdata. install nasm for local user to continue."
    exit 1
}

$tempfile = "$env:TEMP\shellcode.bin"
& $nasm $path -f bin -o $tempfile
'{ ' + ((format-hex $tempfile | select -expand bytes | % { '0x{0:x2}' -f $_ }) -join ', ') + ' }'