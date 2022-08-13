# kptnhook

## TL;DL
Kptnhooks aim is to assist in global api hooking for security research and reverse engineering.
I'm using a kernel driver to ensure each and every process is accessible, from the first processes started by windows before even the login screen. Certain security mitigations have to be disabled from the kernel side for this to work, as some windows processes have special protections against hooking and injection.

## Status
This is still highly WIP. The kerneldriver is correctly injecting into 32 and 64bit processes without crashing any of them but the dll is not doing anything yet. Here is my TODO list:
- [ ] injected dll should provide hooks and allow sideloading of user-provided dlls
- [ ] disable PPL to allow loading of user-provided dlls
- [ ] provide prebuild binaries
- [ ] provide install/uninstall scripts that disable driver signature enforcement and trust the test certificate
- [ ] instructions / guide and whitepaper