# Usermode rootkit detector

This project is designed to inspect and compare the NTDLL memory sections of running processes against the disk version of `ntdll.dll` in Windows systems. Its primary goal is to detect potential modifications indicative of usermode rootkits. Since the only way for usermode rootkit to exist is hooking NtResumeThread, or its neighbouring functions during thread creation to achieve persistence, checking ntdll's integrity is a viable way of observing rootkit's presence. Other methods of persistence include patching import table, however it is not reliable, since ntdll does not have an import table, thus leaving the .text section the only candidate for usermode hooks.

## Features

- Parses `ntdll.dll` directly from disk to retrieve the `.text` section.
- Parses the `.text` section of `ntdll.dll` loaded in each running process's memory.
- Compares these sections to identify discrepancies.
- Works for both wow64 and 64bit processes.
- Provides a summary of potentially patched processes, aiding in the detection of usermode rootkits.

## Requirements

- Windows operating system.
- (Optional) Administrator privileges for process memory inspection.

## Building

1. Clone this repository to your local machine using Git:

```git clone https://github.com/yourusername/ntdll-integrity-checker.git```

2. Compile either via a provided make.bat (gcc toolchain) or on your own with msvc or something.

## Notes

Tested against publicly available usermode rootkits:

- [r77](https://bytecode77.com/)
- [My own one](https://github.com/forentfraps/rootkit-userland), it does not replicate itself, however the scanner does detect altered processes

