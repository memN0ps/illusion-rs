use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Failed take a snapshot of the specified processes: {0}")]
    FailedToCreateSnapshot(u32),

    #[error("Failed to retrieve information about the first process: {0}")]
    FailedToGetFirstProcess(u32),

    #[error("Failed to retrieve information about the next process: {0}")]
    FailedToGetNextProcess(u32),

    #[error("Failed to retrieve information about the first module:: {0}")]
    FailedToGetFirstModule(u32),

    #[error("Failed retrieve information about the next module: {0}")]
    FailedToGetNextModule(u32),
}
