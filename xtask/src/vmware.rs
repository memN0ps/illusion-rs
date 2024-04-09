use {
    crate::{copy_artifacts_to, DynError, TestVm, UnixCommand},
    std::{fs, io::Write, path::Path, process::Command},
};

/// A struct representing a VMware VM.
pub struct Vmware {}

impl TestVm for Vmware {
    /// Deploys the bootloader and kernel to a VMware VM.
    ///
    /// # Arguments
    ///
    /// * `release` - Whether to build projects in release mode.
    ///
    /// # Returns
    ///
    /// * If the deployment is successful, this function returns `Ok(())`. Otherwise, it returns an error.
    fn deploy(&self, release: bool) -> Result<(), DynError> {
        let output = UnixCommand::new("dd")
            .args([
                "if=/dev/zero",
                "of=/tmp/vmware_cd.img",
                "bs=1k",
                "count=2880",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!("dd command failed with error: {:?}", output.stderr).into());
        }

        let output = UnixCommand::new("mformat")
            .args(["-i", "/tmp/vmware_cd.img", "-f", "2880", "::"])
            .output()?;
        if !output.status.success() {
            return Err(format!("mformat command failed with error: {:?}", output.stderr).into());
        }

        copy_artifacts_to("/tmp/vmware_cd.img", release)?;

        let output = UnixCommand::new("mkisofs")
            .args([
                "-eltorito-boot",
                "vmware_cd.img",
                "-no-emul-boot",
                "-o",
                "/tmp/vmware_cd.iso",
                "/tmp/vmware_cd.img",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!("mkisofs command failed with error: {:?}", output.stderr).into());
        }

        // Append the UEFI shell boot setting to the VMX file
        append_uefi_boot_setting(
            "/mnt/c/Users/memN0ps/Documents/Virtual Machines/Class_Windows/Class_Windows.vmx",
        )?;

        Ok(())
    }

    /// Starts the VMware VM using `vmrun`.
    ///
    /// # Returns
    ///
    /// * If the VM is started successfully, this function returns `Ok(())`. Otherwise, it returns an error.
    fn run(&self) -> Result<(), DynError> {
        let vmrun_path = "/mnt/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe";

        // Use `wslpath` to convert WSL path to Windows path for VMware compatibility
        let vmx_path_wsl =
            "/mnt/c/Users/memN0ps/Documents/Virtual Machines/Class_Windows/Class_Windows.vmx";
        let vmx_path_windows = Command::new("wslpath")
            .arg("-w")
            .arg(vmx_path_wsl)
            .output()
            .map_err(|e| format!("Failed to run wslpath: {:?}", e))?
            .stdout;
        let vmx_path = String::from_utf8(vmx_path_windows)
            .map_err(|e| format!("Failed to parse output from wslpath: {:?}", e))?
            .trim()
            .to_string();

        if !Path::new(vmrun_path).exists() {
            return Err(format!("vmrun executable not found at path: {}", vmrun_path).into());
        }

        println!("🕒 Starting the VMware VM...");
        let output = Command::new(vmrun_path)
            .args(["-T", "ws", "start", &vmx_path])
            .output()?;

        if !output.status.success() {
            let error_details = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to start VM using vmrun: {}", error_details).into());
        }

        println!("🕒 VM started successfully.");
        Ok(())
    }
}

/// Appends a UEFI boot setting to the specified VMX file.
///
/// # Arguments
///
/// * `vmx_path` - Path to the .vmx file.
///
/// # Returns
///
/// * If the setting is appended successfully, this function returns `Ok(())`. Otherwise, it returns an error.
fn append_uefi_boot_setting(vmx_path: &str) -> Result<(), DynError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(vmx_path)?;

    writeln!(file, "bios.forceSetupOnce = \"TRUE\"")?;
    println!("Appended UEFI boot setting to VMX file: {}", vmx_path);
    Ok(())
}
