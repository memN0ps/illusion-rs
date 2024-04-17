use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

fn main() -> io::Result<()> {
    let config = Config::new(
        r"C:\Users\memN0ps\Documents\GitHub\illusion-rs\target\x86_64-unknown-uefi\debug",
        r"D:\",
        r"C:\Users\memN0ps\Documents\Virtual Machines\Class_Windows\Class_Windows.vmx",
        r"C:\Users\memN0ps\Documents\GitHub\illusion-rs\logs.txt",
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    );

    prepare_log_file(&config.log_file_path)?;
    perform_file_operations(&config)?;
    append_to_file(config.vmx_path, "bios.forceSetupOnce = \"TRUE\"")?;
    start_vm(&config)?;
    wait_for_log_creation(&config.log_file_path);
    monitor_logs(&config.log_file_path);

    Ok(())
}

/// Holds configuration for paths used in the program.
struct Config<'a> {
    efi_file_paths: &'a str,
    usb_file_path: &'a str,
    vmx_path: &'a str,
    log_file_path: &'a str,
    vmrun_path: &'a str,
}

impl<'a> Config<'a> {
    fn new(
        efi_file_paths: &'a str,
        usb_file_path: &'a str,
        vmx_path: &'a str,
        log_file_path: &'a str,
        vmrun_path: &'a str,
    ) -> Self {
        Config {
            efi_file_paths,
            usb_file_path,
            vmx_path,
            log_file_path,
            vmrun_path,
        }
    }
}

/// Removes the existing log file if it exists to start fresh.
fn prepare_log_file(path: &str) -> io::Result<()> {
    if Path::new(path).exists() {
        fs::remove_file(path)?;
        println!("Existing log file removed.");
    }
    Ok(())
}

/// Copies EFI files and lists files in the specified directory.
fn perform_file_operations(config: &Config) -> io::Result<()> {
    copy_efi_files(config.efi_file_paths, config.usb_file_path)?;
    list_files(config.usb_file_path)
}

/// Appends a specified line of text to a file, ensuring the file is open for writing.
fn append_to_file(file_path: &str, content: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true) // Ensures that data is written to the end of the file.
        .write(true) // Explicitly allows writing to the file.
        .open(file_path)?;

    writeln!(file, "{}", content)?;
    println!("Appended to '{}': {}", file_path, content);
    Ok(())
}

/// Copies EFI files to the destination.
fn copy_efi_files(source: &str, destination: &str) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let path = entry?.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("efi") {
            let dest_path = Path::new(destination).join(path.file_name().unwrap());
            fs::copy(&path, &dest_path)?;
            println!("Copied '{}' to '{}'", path.display(), dest_path.display());
        }
    }
    Ok(())
}

/// Lists files in the specified directory.
fn list_files(path: &str) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        println!("{:?}", path.display());
    }
    Ok(())
}

/// Waits for the log file to be created after starting the VM.
fn wait_for_log_creation(log_file_path: &str) {
    while !Path::new(log_file_path).exists() {
        println!("Waiting for log file to be created...");
        thread::sleep(Duration::from_millis(1000));
    }
    println!("Log file detected.");
}

/// Monitors the log file and prints new lines as they are added.
fn monitor_logs(path: &str) {
    let mut file = BufReader::new(File::open(path).expect("Failed to open log file"));
    file.seek(SeekFrom::End(0))
        .expect("Failed to seek in log file");

    loop {
        let mut buf = String::new();
        if file.read_line(&mut buf).expect("Failed to read line") > 0 {
            print!("{}", buf);
        } else {
            thread::sleep(Duration::from_millis(500)); // Sleep if no new data
        }
    }
}

/// Starts a VMware VM using the vmrun command without blocking the main program.
fn start_vm(config: &Config) -> io::Result<()> {
    println!("Starting VMware VM...");
    let child = Command::new(config.vmrun_path)
        .args(["-T", "ws", "start", config.vmx_path, "gui"])
        .spawn()?; // Spawns the command as a non-blocking subprocess
    println!(
        "VM has been started (process detached). Process ID: {}",
        child.id()
    );
    Ok(())
}
