// Credits to Satoshi Tanda: https://github.com/tandasat/Hypervisor-101-in-Rust/tree/main/xtask

use {
    clap::{Parser, Subcommand},
    std::{
        env, fs,
        path::{Path, PathBuf},
        process::Command,
    },
    vmware::Vmware,
};

mod vmware;

/// A custom error type used across this application for uniform error handling.
type DynError = Box<dyn std::error::Error>;

/// Defines the command line interface using the clap crate.
#[derive(Parser)]
#[command(author, about, long_about = None)]
struct Cli {
    /// Flag to indicate whether to build the hypervisor using the release profile.
    #[arg(short, long)]
    release: bool,

    /// Subcommands for the CLI application.
    #[command(subcommand)]
    command: Commands,
}

/// Defines subcommands available in the CLI.
#[derive(Subcommand)]
enum Commands {
    /// Subcommand to start a VMware VM.
    Vmware,
}

fn main() {
    let cli = Cli::parse();
    println!("Parsed CLI arguments.");
    let result = match &cli.command {
        Commands::Vmware => {
            println!("Command 'Vmware' selected.");
            start_vm(&Vmware {}, cli.release)
        }
    };

    if let Err(e) = result {
        eprintln!("Error occurred: {}", e);
        std::process::exit(-1);
    }
}

/// Starts the virtual machine deployment process.
///
/// # Arguments
///
/// * `vm` - A trait object that can perform VM deployment and execution.
/// * `release` - Whether to build projects in release mode.
///
/// # Returns
///
/// * If the VM deployment and execution are successful, this function returns `Ok(())`. Otherwise, it returns an error.
fn start_vm<T: TestVm>(vm: &T, release: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VM deployment...");
    build_loader(release)?;
    build_uefi(release)?;
    println!("Projects built successfully. Deploying VM...");
    vm.deploy(release)?;
    println!("VM deployed. Running VM...");
    vm.run()
}

/// Trait defining the operations required for VM management.
trait TestVm {
    fn deploy(&self, release: bool) -> Result<(), DynError>;
    fn run(&self) -> Result<(), DynError>;
}

/// Builds a specified project using cargo.
///
/// # Arguments
///
/// * `project` - The name of the project directory to build.
/// * `release` - Whether to build in release mode.
/// * `target` - Optional cross-compilation target.
///
/// # Returns
///
/// * If the project is built successfully, this function returns `Ok(())`. Otherwise, it returns an error.
fn build_project(project: &str, release: bool, target: Option<&str>) -> Result<(), DynError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let project_dir = project_root_dir().join(project);
    println!("Building project '{}' in {:?}...", project, project_dir);

    let mut command = Command::new(&cargo);
    command.current_dir(&project_dir).arg("build");

    if let Some(target_spec) = target {
        command.args(["--target", target_spec]);
        println!("Setting target: {}", target_spec);
    }

    if release {
        command.arg("--release");
        println!("Building in release mode...");
    } else {
        println!("Building in debug mode...");
    }

    let output = command.output()?;
    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("Build failed with error: {}", error_message);
        Err("Cargo build failed".into())
    } else {
        println!("Build completed successfully.");
        Ok(())
    }
}

/// Builds the loader project using cargo.
///
/// # Arguments
///
/// * `release` - Whether to build in release mode.
///
/// # Returns
///
/// * If the project is built successfully, this function returns `Ok(())`. Otherwise, it returns an error.
fn build_loader(release: bool) -> Result<(), DynError> {
    build_project("loader", release, None)
}

/// Builds the UEFI project using cargo.
///
/// # Arguments
///
/// * `release` - Whether to build in release mode.
///
/// # Returns
///
/// * If the project is built successfully, this function returns `Ok(())`. Otherwise, it returns an error.
fn build_uefi(release: bool) -> Result<(), DynError> {
    build_project("uefi", release, Some("x86_64-unknown-uefi"))
}

/// Constructs the project root directory path.
///
/// # Returns
///
/// * The path to the project root directory.
fn project_root_dir() -> PathBuf {
    // Get the path to illusion/xtask directory and resolve its parent directory.
    let root_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf();
    fs::canonicalize(root_dir).unwrap()
}

/// Copies EFI files to the specified VM image using mcopy.
///
/// # Arguments
///
/// * `image` - Path to the VM image.
/// * `release` - Whether the artifacts are from a release build.
///
/// # Returns
///
/// * If the files are copied successfully, this function returns `Ok(())`. Otherwise, it returns an error.
fn copy_artifacts_to(image: &str, release: bool) -> Result<(), DynError> {
    // Function to derive the output directory path based on the build mode.
    fn output_dir(release: bool) -> PathBuf {
        let mut out_dir = project_root_dir();
        out_dir.extend(&["target", "x86_64-unknown-uefi"]);
        out_dir.extend(if release { &["release"] } else { &["debug"] });
        fs::canonicalize(out_dir).unwrap()
    }

    // Correcting file paths for 'loader.efi' and 'illusion.efi'
    let loader_efi = output_dir(release)
        .join("loader.efi")
        .to_string_lossy()
        .to_string();
    let illusion_efi = output_dir(release)
        .join("illusion.efi")
        .to_string_lossy()
        .to_string();
    let files = [loader_efi, illusion_efi];

    // Copying each file to the specified image using mcopy
    for file in files.iter() {
        println!("Copying file '{}' to image '{}'.", file, image);
        let output = UnixCommand::new("mcopy")
            .args(["-o", "-i", image, &file, "::/"])
            .output()?;

        if !output.status.success() {
            let error_message = String::from_utf8_lossy(&output.stderr);
            println!("Failed to copy with error: {}", error_message);
            return Err(format!("mcopy failed for file '{}': {}", file, error_message).into());
        }
    }

    println!("All files copied successfully.");
    Ok(())
}

// Defines [`UnixCommand`] that wraps [`Command`] with `wsl` command on Windows.
// On non-Windows platforms, it is an alias of [`Command`].
cfg_if::cfg_if! {
    if #[cfg(windows)] {
        struct UnixCommand {
            wsl: Command,
            program: String,
        }

        impl UnixCommand {
            fn new(program: &str) -> Self {
                Self {
                    wsl: Command::new("wsl"),
                    program: program.to_string(),
                }
            }

            pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Command
            where
                I: IntoIterator<Item = S>,
                S: AsRef<std::ffi::OsStr>,
            {
                self.wsl.arg(self.program.clone()).args(args)
            }
        }
    } else {
        type UnixCommand = Command;
    }
}
