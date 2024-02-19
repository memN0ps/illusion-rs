# Ensure the EFI\Boot directory structure exists on the USB drive D:\ and create if necessary
$efiBootDir = "D:\illusion.efi"
New-Item -ItemType Directory -Path $efiBootDir -Force

# Copy the EFI application to the EFI\Boot directory, renaming it to bootx64.efi
$efiFilePath = "C:\Users\memN0ps\Documents\GitHub\illusion-rs\target\x86_64-unknown-uefi\debug\illusion.efi"
Copy-Item -Path "$efiFilePath" -Destination "$efiBootDir"

# Print the contents of the D:\ drive to verify the copy operation
Get-ChildItem -Path D:\ -Recurse

# Define the path to the VMX file and vmrun.exe
$vmxPath = "C:\Users\memN0ps\Documents\Virtual Machines\Windows-10-UEFI-Dev\Windows-10-UEFI-Dev.vmx"
$vmrunPath = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# Append configuration to the VMX file for booting into firmware setup on next boot
Add-Content -Path "$vmxPath" -Value "bios.forceSetupOnce = `"`TRUE`""

# Start the VMware VM and open the GUI. Attempt to boot to firmware (if supported).
& "$vmrunPath" -T ws start "$vmxPath" gui
