use crate::anything;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Running,
    Stopped,
}

pub trait VMRun {
    fn vmrun(&self, args: &Vec<&str>) -> anything::Result<String>;
    fn state(&self) -> anything::Result<VmState>;
    fn start(&self, nogui: bool) -> anything::Result<()>;
    fn stop(&self, hard: bool) -> anything::Result<()>;
}

impl VMRun for super::VMWare {
    fn vmrun(&self, args: &Vec<&str>) -> anything::Result<String> {
        let output = std::process::Command::new("vmrun").args(args).output()?;

        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            Ok(stdout)
        } else {
            let stderr = String::from_utf8(output.stderr)?;
            Err(stderr.into())
        }
    }

    fn state(&self) -> anything::Result<VmState> {
        let list = self.vmrun(&vec!["list"])?;

        if list.contains(self.vmx_path.as_str()) {
            Ok(VmState::Running)
        } else {
            Ok(VmState::Stopped)
        }
    }

    fn start(&self, nogui: bool) -> anything::Result<()> {
        let mut args = vec!["start", self.vmx_path.as_str()];
        if nogui {
            args.push("nogui");
        }

        self.vmrun(&args)?;
        Ok(())
    }

    fn stop(&self, hard: bool) -> anything::Result<()> {
        let mut args = vec!["stop", self.vmx_path.as_str()];

        if hard {
            args.push("hard");
        } else {
            args.push("soft");
        }

        self.vmrun(&args)?;
        Ok(())
    }
}
