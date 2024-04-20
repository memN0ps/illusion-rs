# Windows UEFI Blue Pill Type-1 Hypervisor in Rust (Codename: Illusion)

![Build Status](https://github.com/memN0ps/illusion-rs/actions/workflows/rust.yml/badge.svg)
![License](https://img.shields.io/github/license/memN0ps/illusion-rs)
![Issues](https://img.shields.io/github/issues/memN0ps/illusion-rs)
![Forks](https://img.shields.io/github/forks/memN0ps/illusion-rs)
![Stars](https://img.shields.io/github/stars/memN0ps/illusion-rs)

A lightweight, memory-safe, and blazingly fast Rust-based type-1 research hypervisor with hooks for Intel VT-x, focused on studying the core concepts of virtualization.

## Features

### PatchGuard Compatible Features

- :white_check_mark: Hidden System Call (Syscall) Hooks Via System Service Descriptor Table (SSDT).
- :white_check_mark: Hidden Kernel Inline Hooks.
- :white_check_mark: Hidden Model Specific Registers (MSR) Hooks.
- :x: Hidden Interrupt Descriptor Table (IDT) Hooks.

### Microsoft Hyper-V Compatible Features

- :white_check_mark: Support for running as a nested hypervisor under Microsoft Hyper-V with Virtualization Based Security (VBS) Enabled.
- :x: Support for running as the primary hypervisor on top of Microsoft Hyper-V with Virtualization Based Security (VBS) Enabled.

### VM Exit Handling

- :white_check_mark: VM Exit Handling: `ExceptionOrNmi (#GP, #PF, #BP, #UD)` (0), `InitSignal` (3), `StartupIpi` (4), `Cpuid` (10), `Getsec` (11), `Hlt` (12), `Invd` (13), `Vmcall` (18), `Vmclear` (19), `Vmlaunch` (20), `Vmptrld` (21), `Vmptrst` (22), `Vmresume` (24), `Vmxon` (27), `Vmxoff` (26), `Rdmsr` (31), `Wrmsr` (32), `MonitorTrapFlag` (37), `Rdtsc` (49), `EptViolation` (48), `EptMisconfiguration` (50), `Invept` (53), `Invvpid` (55), `Xsetbv` (55).

## Supported Hardware

- :white_check_mark: Intel processors with VT-x and Extended Page Tables (EPT) support.
- :x: AMD processors with AMD-V (SVM) and Nested Page Tables (NPT) support.

## Supported Platforms

- :white_check_mark: Windows 10 - Windows 11, x64 only.

## Installation

- Install Rust from [here](https://www.rust-lang.org/tools/install).

## Building the Project

- Development: `cargo build --target x86_64-unknown-uefi --profile dev`.
- Release: `cargo build --target x86_64-unknown-uefi --profile release`.

## Acknowledgments, References, and Motivation

Big thanks to the amazing people and resources that have shaped this project. A special shout-out to everyone listed below. While I didn't use all these resources in my work, they've been goldmines of information, super helpful for anyone diving into hypervisor development, including me.

- **[Daax Rynd (@daaximus)](https://github.com/daaximus), [Aidan Khoury (@ajkhoury)](https://github.com/ajkhoury), [Nick Peterson (@everdox)](https://github.com/everdox)**: For their comprehensive series on hypervisor development:
  - [7 Days to Virtualization](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)
  - [Patchguard: Hypervisor Based Introspection [P1]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p1/)
  - [Patchguard: Hypervisor Based Introspection [P2]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/)
  - [Syscall Hooking Via Extended Feature Enable Register (EFER)](https://revers.engineering/syscall-hooking-via-extended-feature-enable-register-efer/)

- **[Sina Karvandi (@Intel80x86)](https://github.com/SinaKarvandi)**: For the extensive Hypervisor From Scratch series:
  - [Tutorial Series](https://rayanfam.com/tutorials/)
  - [GitHub Repository](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/)

- **[Satoshi Tanda(@tandasat)](https://github.com/tandasat/)**: His work has significantly influenced this project:
  - [Hypervisor Development for Security Researchers](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html)
  - [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust)
  - Additional Projects: [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp), [DdiMon](https://github.com/tandasat/DdiMon), [HyperPlatform](https://github.com/tandasat/HyperPlatform), [MiniVisorPkg](https://github.com/tandasat/MiniVisorPkg)
 
- **[Matthias @not-matthias](https://github.com/not-matthias/amd_hypervisor)**: For his impactful work on the [amd_hypervisor](https://github.com/not-matthias/amd_hypervisor) project, which greatly inspired and influenced this research.

#### Community and Technical Resources

- **[Secret Club](https://github.com/thesecretclub)**: Insights into anti-cheat systems and hypervisor detection, which also inspired this project:
  - [System emulation detection](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) by [@Daax](https://github.com/daaximus), [@iPower](https://github.com/iPower), [@ajkhoury](https://github.com/ajkhoury), [@drew](https://github.com/drew-gpf)
  - [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html) by [@vmcall](https://github.com/vmcall), [@Daax](https://github.com/daaximus)

- **Other Essential Resources**:
  - [Intel's Software Developer's Manual](https://www.intel.com/)
  - [Maurice Heumann's (@momo5502)](https://github.com/momo5502/) [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)
  - [Guided Hacking's](https://guidedhacking.com/) [x64 Virtual Address Translation](https://www.youtube.com/watch?v=W3o5jYHMh8s) on YouTube
  - [UnKnoWnCheaTs](https://unknowncheats.me/) [forum post](https://www.unknowncheats.me/forum/2779560-post4.html) by [@namazso](https://github.com/namazso)
  - [RVM1.5](https://github.com/rcore-os/RVM1.5), [Barbervisor](https://github.com/Cisco-Talos/Barbervisor), [rustyvisor](https://github.com/iankronquist/rustyvisor), [orange_slice](https://github.com/gamozolabs/orange_slice), [mythril](https://github.com/mythril-hypervisor/mythril), [uhyve](https://github.com/hermit-os/uhyve), [maystorm](https://github.com/neri/maystorm)
  - [AMD-V Hypervisor Development by Back Engineering](https://blog.back.engineering/04/08/2022), [bluepill by @_xeroxz](https://git.back.engineering/_xeroxz/bluepill)
  - [hvpp by @wbenny](https://github.com/wbenny/hvpp)
  - [HyperHide by @Air14](https://github.com/Air14/HyperHide)
  - [How AetherVisor works under the hood by M3ll0wN1ght](https://mellownight.github.io/AetherVisor)
  - [Rust library to use x86 (amd64) specific functionality and registers (x86 crate for Rust)](https://github.com/gz/rust-x86)
  - [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html).
  - [Joanna Rutkowska: Pioneering the Blue Pill Hypervisor Concept, one of the earliest proofs of concept](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html)

#### Helpers and Collaborators

Special thanks to:
- [Daax Rynd](https://revers.engineering/)
- [Satoshi Tanda (@tandasat)](https://github.com/tandasat)
- [Drew (@drew)](https://github.com/drew-gpf)
- [iPower (@iPower)](https://github.com/iPower)
- [Namazso (@namazso)](https://github.com/namazso)
- [Matthias @not-matthias](https://github.com/not-matthias/)
- [@felix-rs / @joshuа](https://github.com/felix-rs)
- Jess (@jessiep_)
- [Ryan McCrystal / @rmccrystal](https://github.com/rmccrystal)
- [Jim Colerick (@vmprotect)](https://github.com/thug-shaker)

## License

This project is licensed under the MIT License. For more information, see the [MIT License details](./LICENSE).
