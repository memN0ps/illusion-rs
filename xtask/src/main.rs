#![feature(negative_impls, auto_traits, const_type_id)]

use {
    crate::vmware::{
        vmrun::{VMRun, VmState},
        VMWare,
    },
    log::{debug, error, info, warn},
    std::{
        io::{BufRead, Seek},
        path::PathBuf,
        sync::Arc,
    },
};

pub mod anything;
pub mod vmware;

const ROOT: &'static str = "E:";
const VMX_PATH: &'static str = r"C:\Users\memN0ps\Documents\Virtual Machines\Hv\Hv.vmx";
// const VMX_PATH: &'static str = r"C:\Users\memN0ps\Documents\Virtual Machines\WinDev2404Eval.VMWare\Dev.vmx";
const LOG_PATH: &'static str = r"C:\Users\memN0ps\Documents\GitHub\illusion-rs\logs.txt";
const BOOT_PATH: &'static str = r"\EFI\Boot";
const LOADER_PATH: &'static str = r"C:\Users\memN0ps\Documents\GitHub\illusion-rs\target\x86_64-unknown-uefi\debug\loader.efi";
const HYPERVISOR_PATH: &'static str = r"C:\Users\memN0ps\Documents\GitHub\illusion-rs\target\x86_64-unknown-uefi\debug\illusion.efi";
const BOOTX64_NAME: &'static str = "bootx64.efi";
const HYPERVISOR_NAME: &'static str = "illusion.efi";

fn install_bootx64(root: &PathBuf, bootx64_path: &PathBuf, hypervisor_path: &PathBuf) -> anything::Result<()> {
    // check if the path exists
    if !bootx64_path.exists() {
        return Err(format!("Source {} does not exist", bootx64_path.to_string_lossy()).into());
    }

    // create /efi/boot if it doesn't exist
    let dest = root.join(BOOT_PATH);
    if !dest.exists() {
        std::fs::create_dir_all(&dest)?;
        debug!("Created directory {}", dest.to_string_lossy());
    }

    // copy to dest
    std::fs::copy(bootx64_path, dest.join(BOOTX64_NAME))?;
    debug!("Copied bootx64.efi from {} to {}", bootx64_path.to_string_lossy(), dest.to_string_lossy());

    // copy to dest
    std::fs::copy(hypervisor_path, dest.join(HYPERVISOR_NAME))?;
    debug!("Copied bootx64.efi from {} to {}", hypervisor_path.to_string_lossy(), dest.to_string_lossy());

    Ok(())
}

fn clear_logs(log_path: &PathBuf) -> anything::Result<()> {
    if log_path.exists() {
        std::fs::write(log_path, "")?;
    }

    Ok(())
}

fn serial_loop(vm: &VMWare, log_path: &PathBuf) -> anything::Result<()> {
    let mut cursor = 0;
    let mut file = std::fs::OpenOptions::new().read(true).open(log_path)?;

    // setup exit handler
    let shared_vm = Arc::new(vm.clone());
    ctrlc::set_handler(move || {
        debug!("Received termination, stopping VM...");
        if shared_vm.stop(false).is_ok() {
            info!("VM Terminated");
            return;
        }

        // force terminate
        warn!("Failed to stop VM, forcing termination...");
        if shared_vm.stop(true).is_ok() {
            info!("VM Terminated");
            return;
        }

        error!("Failed to terminate VM");
    })?;

    // read serial output
    while let Ok(VmState::Running) = vm.state() {
        file.seek(std::io::SeekFrom::Start(cursor))?;

        let mut reader = std::io::BufReader::new(&file);
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            print!("{}", line);
            line.clear();
        }

        cursor = file.seek(std::io::SeekFrom::Current(0))?;
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    info!("Exited serial loop");
    Ok(())
}

fn wait_vm_termination(vm: &VMWare) {
    // wait for vm to terminate
    while let Ok(VmState::Running) = vm.state() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn main() -> anything::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Trace).init();

    let bootx64 = dunce::canonicalize(LOADER_PATH)?;

    let log = PathBuf::from(LOG_PATH);
    let vmx = PathBuf::from(VMX_PATH);
    let root = PathBuf::from(ROOT);
    let hypervisor_path = PathBuf::from(HYPERVISOR_PATH);

    let vm = VMWare::new(&vmx)?;

    debug!("Checking VM...");
    if vm.state()? == VmState::Running {
        info!("Terminate already running VM");
        vm.stop(true)?;
    }

    debug!("Installing UEFI...");
    install_bootx64(&root, &bootx64, &hypervisor_path)?;
    info!("Installed UEFI to {}", root.to_string_lossy());

    clear_logs(&log)?;
    debug!("Cleared logs");

    debug!("Launching VM from {}", VMX_PATH);
    vm.start(true)?;
    info!("Launched VM");

    debug!("Entering serial loop...");
    serial_loop(&vm, &log)?;

    info!("Waiting for VM termination...");
    wait_vm_termination(&vm);

    info!("Bye!");
    Ok(())
}
