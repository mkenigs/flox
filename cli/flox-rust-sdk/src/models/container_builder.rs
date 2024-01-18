use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use thiserror::Error;

pub struct ContainerBuilder {
    path: PathBuf,
}

impl ContainerBuilder {
    /// Wrap a container builder script at the given path
    ///
    /// Typically this will be created by [LockedManifest::build_container]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn stream_container(&self, mut sink: impl Write) -> Result<(), ContainerBuilderError> {
        let mut container_builder_command = Command::new(&self.path);
        container_builder_command.stdout(Stdio::piped());

        let handle = container_builder_command
            .spawn()
            .map_err(ContainerBuilderError::CallContainerBuilder)?;
        let mut stdout = handle.stdout.expect("stdout set to piped");

        io::copy(&mut stdout, &mut sink).map_err(ContainerBuilderError::StreamContainer)?;

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ContainerBuilderError {
    #[error("failed to call container builder")]
    CallContainerBuilder(#[source] std::io::Error),
    #[error("failed to stream container to sink")]
    StreamContainer(#[source] std::io::Error),
}