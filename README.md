# Windows UEFI Blue Pill Type-1 Hypervisor in Rust (Codename: Illusion)

![Build Status](https://github.com/memN0ps/illusion-rs/actions/workflows/rust.yml/badge.svg)
![License](https://img.shields.io/github/license/memN0ps/illusion-rs)
![Issues](https://img.shields.io/github/issues/memN0ps/illusion-rs)
![Forks](https://img.shields.io/github/forks/memN0ps/illusion-rs)
![Stars](https://img.shields.io/github/stars/memN0ps/illusion-rs)

A lightweight, memory-safe, and blazingly fast Rust-based type-1 research hypervisor with hooks for Intel VT-x, focused on studying the core concepts of virtualization.

**Note:** The [**Illusion** hypervisor](https://github.com/memN0ps/illusion-rs) (Windows UEFI Blue Pill Type-1 Hypervisor in Rust) is more stable, supports more features, and is overall better designed. The [**Matrix** hypervisor](https://github.com/memN0ps/matrix-rs) (Windows Kernel Blue Pill Type-2 Hypervisor in Rust) is an older, experimental version and is not intended for production use. Both projects serve as templates to help people get started with hypervisor development in Rust.

## Description

This diagram illustrates the mechanism of translating x64 virtual addresses to physical addresses and the Extended Page Tables (EPT) used in hardware-assisted virtualization. In x64 systems, the translation involves four tables: PML4, PDPT, PDT, and PT, each using 9 bits to point to the next table, finally mapping to the physical RAM address.

![EPT](./images/virtual_address_translation.png)
**Figure 1: x64 Virtual Address Translation (Full Credits: [Guided Hacking](https://guidedhacking.com/threads/x64-virtual-address-translation.20416/))**

Extended Page Tables (EPT), used in technologies like Intel VT-x and AMD-v's (SVM) Nested Page Tables (NPT), provide a Second Layer of Address Translation (SLAT). EPT maps guest physical addresses to host physical addresses, reducing VM exits and improving performance. While traditional paging translates virtual to physical addresses, EPT adds another layer, translating guest physical addresses to host physical addresses. This dual-layer approach in EPT involves two sets of page tables: one managed by the guest OS and the other by the hypervisor. The guest OS page tables translate virtual addresses to guest physical addresses, while the EPT tables map these guest physical addresses to the actual host physical addresses, enabling efficient virtualization with minimal overhead.

The diagram below illustrates the structure and flow of the Windows UEFI Blue Pill Type-1 Hypervisor written in Rust, demonstrating the use of Extended Page Table (EPT) hooks.
![EPT](./images/illusion.drawio.png)
**Figure 2: Extended Page Tables (EPT) Hooks (Illusion)**

## Features

### PatchGuard Compatible Features

- :white_check_mark: Hidden System Call (Syscall) Hooks Via System Service Descriptor Table (SSDT).
- :white_check_mark: Hidden Kernel Inline Hooks.
- :white_check_mark: Hidden Model Specific Registers (MSR) Hooks.
- :x: Hidden Interrupt Descriptor Table (IDT) Hooks.
- :x: Hidden Hardware Debug Register Breakpoints.

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

## Usage

1. **Build the Project**

   Follow the build instructions provided in the previous sections to compile the project.

2. **Set Up VMware Workstation**

   Configure VMware Workstation to boot into the firmware setup on the next boot and to use the physical USB drive as the boot device:

   - **Add a Hard Disk:**
     - Go to `VM -> Settings -> Hardware -> Add -> Hard Disk -> Next -> SCSI or NVMe (Recommended) -> Next -> Use a physical disk (for advanced users) -> Next -> Device: PhysicalDrive1 and Usage: Use entire disk -> Next -> Finish.`
   - **Add a Serial Port:**
     - Go to `VM -> Settings -> Add Serial Port -> Finish`.
     - Select `Use output file: C:\Users\memN0ps\Documents\GitHub\illusion-rs\logs.txt` to direct the Serial Port output from COM1 to the `logs.txt` file. (You can choose any location, but the preference is within the project directory).
   - **Boot Options:**
     - If you're not using the automated PowerShell script, start the VM by clicking `Power On to Firmware`.
     - Select `Internal Shell (Unsupported option)` or `EFI VMware Virtual SCSI Hard Drive (1.0)`.

3. **Run the PowerShell Script**

   Execute the following PowerShell script to automate the setup process. Make sure to modify the paths according to your environment.

   ```powershell
   ### Change paths according to your environment ###

   # Set build type to either 'debug' or 'release'
   $buildType = "debug" # Use this line for a debug build
   # $buildType = "release" # Uncomment this line and comment the above for a release build

   # Define the file path to copy all EFI files based on the build type
   $efiFilePaths = ".\target\x86_64-unknown-uefi\$buildType\*.efi"

   # Define the destination path on the USB drive D:\
   $usbFilePath = "D:\"

   # Define the path to the VMX file
   $vmxPath = "C:\Users\memN0ps\Documents\Virtual Machines\Class_Windows\Class_Windows.vmx"

   # Define the path to the vmrun.exe file
   $vmrunPath = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

   # Define the path to the log file
   $logFilePath = ".\logs.txt"

   # Copy all EFI applications to the D:\ drive
   Copy-Item -Path $efiFilePaths -Destination $usbFilePath

   # Print the contents of the D:\ drive to verify the copy operation
   Get-ChildItem -Path D:\ -Recurse

   # Append configuration to the VMX file for booting into firmware setup on next boot
   Add-Content -Path $vmxPath -Value "bios.forceSetupOnce = `"TRUE`""

   # Check if the log file exists and delete it if it does
   if (Test-Path $logFilePath) {
       Remove-Item $logFilePath -Force
       Write-Host "Log file $logFilePath deleted."
   }

   # Start the VMware VM and open the GUI. Attempt to boot to firmware (if supported).
   & "$vmrunPath" -T ws start "$vmxPath" gui

   # Wait for the log file to be created (e.g., by another process) before proceeding to tail it
   while (-not (Test-Path $logFilePath)) {
       Start-Sleep -Seconds 1
       Write-Host "Waiting for log file to be created..."
   }

   # Tail the log file to display live updates from the start
   Write-Host "Monitoring log file from the start for updates..."
   Get-Content -Path $logFilePath -Wait
   ```

![VMware Workstation Boot Options](./images/vmware_firmware.png)

4. **Navigate to the USB Drive and Start the Hypervisor**

   In the UEFI Shell, navigate to the USB drive and run the loader (`loader.efi`). The hypervisor will start, followed by the Windows Boot Manager (`bootmgfw.efi`) to boot into Windows.

![VMware Workstation UEFI Shell](./images/vmware_uefi.png)

5. **Interact with the Hypervisor**

   After Windows boots, use `client.exe` to interact with the hypervisor and perform various operations, including checking hypervisor's presence or setting hidden EPT hooks.

![VMware Workstation Client Shell](./images/hypervisor_client.png)

### PoC

Verify the execution of the EPT hooking proof of concept (PoC) by checking the hypervisor's logs (serial port logger through COM ports) and Windbg. A PoC screenshot is provided below.

![VMware Workstation CPUID](./images/hypervisor_poc.png)

## Acknowledgments, References, and Motivation

Big thanks to the amazing people and resources that have shaped this project. A special shout-out to everyone listed below. While I didn't use all these resources in my work, they've been goldmines of information, super helpful for anyone diving into hypervisor development, including me.

- **[Daax Rynd (@daaximus)](https://github.com/daaximus)**: For his outstanding free series on hypervisor development, which is one of the best resources available and has greatly influenced my work with its thorough research and clear explanations. His support and answers to my questions were invaluable in getting me started with hypervisor development:
  - [7 Days to Virtualization](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/).
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/).

- **[Satoshi Tanda (@tandasat)](https://github.com/tandasat)**: Satoshi Tanda's guidance, projects, and structured training programs have been incredibly helpful. His detailed explanations and contributions on GitHub have significantly enhanced my understanding, making him a great mentor throughout my journey:
  - [Hypervisor Development for Security Researchers](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html).
  - [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust).
  - Additional Projects: [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp), [DdiMon](https://github.com/tandasat/DdiMon), [HyperPlatform](https://github.com/tandasat/HyperPlatform), [MiniVisorPkg](https://github.com/tandasat/MiniVisorPkg).

- **[Jess (@jessiep_)](https://github.com/Intege-rs)**: For his invaluable support and collaboration in several areas of this project, providing essential insights and expertise, and for his quick responses to my questions.

- **[Drew (@drew)](https://github.com/drew-gpf)**: For his help, guidance, and quick responses to my questions in various aspects of hypervisor development.

- **[Sina Karvandi (@Intel80x86)](https://github.com/SinaKarvandi)**: For his detailed free Hypervisor From Scratch series:
  - [Tutorial Series](https://rayanfam.com/tutorials/).
  - [GitHub Repository](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/).

- **[Matthias (@not-matthias)](https://github.com/not-matthias)**: For his impactful work on the [amd_hypervisor](https://github.com/not-matthias/amd_hypervisor) project, which greatly inspired and influenced this research.

- **[Nick Peterson (@everdox)](https://github.com/everdox)** and **[Aidan Khoury (@ajkhoury)](https://github.com/ajkhoury)**: For their insightful explorations into hypervisor introspection and syscall hooking:
  - [Patchguard: Hypervisor Based Introspection [P1]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p1/).
  - [Patchguard: Hypervisor Based Introspection [P2]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/).
  - [Syscall Hooking Via Extended Feature Enable Register (EFER)](https://revers.engineering/syscall-hooking-via-extended-feature-enable-register-efer/).

#### Community and Technical Resources

- **[Secret Club](https://github.com/thesecretclub)**: Insights into anti-cheat systems and hypervisor detection, which also inspired this project:
  - [System emulation detection](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) by [@Daax](https://github.com/daaximus), [@iPower](https://github.com/iPower), [@ajkhoury](https://github.com/ajkhoury), [@drew](https://github.com/drew-gpf).
  - [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html) by [@vmcall](https://github.com/vmcall), [@Daax](https://github.com/daaximus).

- **Other Essential Resources**:
  - [Intel's Software Developer's Manual](https://www.intel.com/).
  - [Maurice Heumann's (@momo5502)](https://github.com/momo5502/) [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/).
  - [Guided Hacking's](https://guidedhacking.com/) [x64 Virtual Address Translation](https://www.youtube.com/watch?v=W3o5jYHMh8s) on YouTube.
  - [UnKnoWnCheaTs](https://unknowncheats.me/) [forum post](https://www.unknowncheats.me/forum/2779560-post4.html) by [@namazso](https://github.com/namazso).
  - [RVM1.5](https://github.com/rcore-os/RVM1.5), [Barbervisor](https://github.com/Cisco-Talos/Barbervisor), [rustyvisor](https://github.com/iankronquist/rustyvisor), [orange_slice](https://github.com/gamozolabs/orange_slice), [mythril](https://github.com/mythril-hypervisor/mythril), [uhyve](https://github.com/hermit-os/uhyve), [maystorm](https://github.com/neri/maystorm).
  - [AMD-V Hypervisor Development by Back Engineering](https://blog.back.engineering/04/08/2022), [bluepill by @_xeroxz](https://git.back.engineering/_xeroxz/bluepill).
  - [hvpp by @wbenny](https://github.com/wbenny/hvpp).
  - [HyperHide by @Air14](https://github.com/Air14/HyperHide).
  - [How AetherVisor works under the hood by M3ll0wN1ght](https://mellownight.github.io/AetherVisor).
  - [Rust library to use x86 (amd64) specific functionality and registers (x86 crate for Rust)](https://github.com/gz/rust-x86).
  - [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html).
  - [Joanna Rutkowska: Pioneering the Blue Pill Hypervisor Concept, one of the earliest proofs of concept](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html).

#### Helpers and Collaborators

Special thanks to:
- [Daax Rynd](https://revers.engineering/).
- [Satoshi Tanda (@tandasat)](https://github.com/tandasat).
- [Drew (@drew)](https://github.com/drew-gpf).
- [iPower (@iPower)](https://github.com/iPower).
- [Namazso (@namazso)](https://github.com/namazso).
- [Jess (@jessiep_)](https://github.com/Intege-rs).
- [Matthias @not-matthias](https://github.com/not-matthias/).
- [@felix-rs / @joshuа](https://github.com/felix-rs).
- [Ryan McCrystal / @rmccrystal](https://github.com/rmccrystal).
- [Jim Colerick (@vmprotect)](https://github.com/thug-shaker).
- [Xitan (@xitan)](https://github.com/x1tan).

## License

This project is licensed under the MIT License. For more information, see the [MIT License details](./LICENSE).
