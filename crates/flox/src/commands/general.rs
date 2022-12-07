use std::future::Future;

use anyhow::Result;
use bpaf::Bpaf;
use flox_rust_sdk::{
    flox::Flox,
    nix::{arguments::NixArgs, Run},
    prelude::Stability,
};
use log::debug;
use tempfile::{tempfile, TempDir};

use crate::{commands::channel, config::Config, flox_forward, utils::init_channels};

#[derive(Bpaf, Clone)]
pub struct GeneralArgs {}

impl GeneralCommands {
    pub async fn handle(&self, flox: Flox) -> Result<()> {
        match self {
            _ if !Config::preview_enabled()? => flox_forward().await?,
            _ => todo!(),
        }
        Ok(())
    }
}

#[derive(Bpaf, Clone)]
pub enum GeneralCommands {
    ///access to the gh CLI
    #[bpaf(command, hide)]
    Gh(Vec<String>),

    #[bpaf(command)]
    Nix(#[bpaf(positional("NIX ARGUMENTS"), complete_shell(complete_nix_shell()))] Vec<String>),

    /// configure user parameters
    #[bpaf(command)]
    Config(#[bpaf(external(config_args))] ConfigArgs),

    /// list all available environments
    #[bpaf(command, long("environments"))]
    Envs,
}

#[derive(Bpaf, Clone)]
pub enum ConfigArgs {
    /// list the current values of all configurable paramers
    #[bpaf(short, long)]
    List,
    /// prompt the user to confirm or update configurable parameters.
    #[bpaf(short, long)]
    Remove,
    /// reset all configurable parameters to their default values without further confirmation.
    #[bpaf(short, long)]
    Confirm,
}

fn complete_nix_shell() -> bpaf::ShellComp {
    // Box::leak will effectively turn the String
    // (that is produced by `replace`) insto a `&'static str`,
    // at the cost of giving up memeory management over that string.
    //
    // Note:
    // We could use a `OnceCell` to ensure this leak happens only once.
    // However, this should not be necessary after all,
    // since the completion runs in its own process.
    // Any memory it leaks will be cleared by the system allocator.
    bpaf::ShellComp::Raw {
        zsh: Box::leak(format!("source {}", env!("NIX_ZSH_COMPLETION_SCRIPT")).into_boxed_str()),
        bash: Box::leak(
            format!(
                "source {}; _nix_bash_completion",
                env!("NIX_BASH_COMPLETION_SCRIPT")
            )
            .into_boxed_str(),
        ),
        fish: "",
        elvish: "",
    }
}

pub type ChannelRef = String;
pub type Url = String;
