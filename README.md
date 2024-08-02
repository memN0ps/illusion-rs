# Windows UEFI Blue Pill Type-1 Hypervisor in Rust (Codename: Inception)

A lightweight, memory-safe, and blazingly fast Rust-based type-1 research hypervisor with hooks for Intel VT-x, focused on studying the core concepts of virtualization.

## Features

### PatchGuard Compatible Features

- :white_check_mark: Hidden System Call (Syscall) Hooks Via System Service Descriptor Table (SSDT).
- :white_check_mark: Hidden Kernel Inline Hooks.
- :white_check_mark: Hidden Model Specific Registers (MSR) Hooks.

### Processor-Specific Features

- :white_check_mark: Extended Page Tables (EPT).
- :white_check_mark: Memory Type Range Registers (MTRRs).
- :x: Intel Processor Trace (PT).

### Microsoft Hyper-V Compatible Features

- :x: Support for running as a nested hypervisor under Microsoft Hyper-V (Type-2) with Virtualization Based Security (VBS) Enabled.
- :x: Support for running as the primary hypervisor on top of Microsoft Hyper-V (Type-1) with Virtualization Based Security (VBS) Enabled.

### VM Exit Handling

- :white_check_mark: VM Exit Handling: `ExceptionOrNmi (#GP, #PF, #BP, #UD)` (0), `InitSignal` (3), `StartupIpi` (4), `Cpuid` (10), `Getsec` (11), `Hlt` (12), `Invd` (13), `Vmcall` (18), `Vmclear` (19), `Vmlaunch` (20), `Vmptrld` (21), `Vmptrst` (22), `Vmresume` (24), `Vmxon` (27), `Vmxoff` (26), `Rdmsr` (31), `Wrmsr` (32), `MonitorTrapFlag` (37), `Rdtsc` (49), `EptViolation` (48), `EptMisconfiguration` (50), `Invept` (53), `Invvpid` (55), `Xsetbv` (55).

### Hypervisor Detection

- :x: Neither basic nor advanced techniques to evade hypervisor detection will be implemented in the public version of this hypervisor.

### Isolation and Security

- :white_check_mark: Custom implementations of the Global Descriptor Table (GDT), Interrupt Descriptor Table (IDT), and Page Tables to enhance the security and isolation of the hypervisor.

## Supported Hardware

- :white_check_mark: Intel processors with VT-x and Extended Page Tables (EPT) support.
- :x: AMD processors with AMD-V (SVM) and Nested Page Tables (NPT) support.

## Supported Platforms

- :white_check_mark: Windows 10 - Windows 11, x64 only.

## Installation

- Install Rust from [here](https://www.rust-lang.org/tools/install).
- Install cargo-make: `cargo install cargo-make`.

## Building the Project

- Debug: `cargo make build-debug`.
- Release: `cargo make build-release`.

## Debugging

- **Serial Port Logging**: Use a serial port logger to capture logs from the hypervisor.

#### Enabling Debug Modes

- Test Mode: Activate test signing with `bcdedit.exe /set testsigning on`.
- Windows Debugging: Follow the steps in this [Microsoft guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug).

```powershell
bcdedit.exe /bootdebug {bootmgr} on
bcdedit.exe /bootdebug on
bcdedit.exe /debug on
```

#### Network Debugging with Windbg

- Setup: `bcdedit.exe /dbgsettings net hostip:w.x.y.z port:n`.

## License

This project is licensed under the MIT License. For more information, see the [MIT License details](./LICENSE).
