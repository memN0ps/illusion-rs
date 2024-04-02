# Loader

The loader is a simple EFI application which searches the available file systems to first load the illusion hypervisor (`illusion.efi`) and then start Windows (`bootmgfw.efi`).

## Usage

Build the loader (`$ cargo build --target x86_64-unknown-uefi --profile release --package loader`) and copy the loader (`EFI/Boot/bootx64.efi`) as well as the hypervisor (`EFI/Boot/illusion.efi`) to your boot disk. The loader will automatically start the hypervisor and Windows.