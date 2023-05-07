/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use clap::Parser;
use std::fmt;
use std::path::Path;

pub enum CfgStatus {
    FileExists,
    FileNotExists,
    NoArg,
}

#[derive(Debug)]
pub enum ArgError {
    NoPathProvided,
}

// Implementong the Error trait for ArgError
impl std::error::Error for ArgError {}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArgError::NoPathProvided => {
                write!(f, "Unable to use config_location when no path is provided!")
            }
        }
    }
}

#[derive(Parser, Debug, Default)]
pub struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: String,
    #[arg(short, long, default_value = "7463")] // ASCII for <3
    port: u16,
    #[arg(long, default_value = "0")]
    rl1_window: u64,
    #[arg(long, default_value = "0")]
    rl1_max: u32,
    #[arg(long, default_value = "0")]
    rl2_window: u64,
    #[arg(long, default_value = "0")]
    rl2_max: u32,
    #[clap(short, long, default_value = "false")]
    zzz_remove_me_firewall_ban: bool,
    #[clap(short, long, default_value=None)]
    config_location: Option<String>,
    #[clap(short, long, default_value="/var/models/manifest.json")]
    manifest_location: String,
    #[clap(short, long, default_value="/usr/bin/python3 /var/models/fex.py")]
    feature_extraction_script: String,
}

impl Args {
    pub fn config_exists(&self) -> CfgStatus {
        match &self.config_location {
            None => CfgStatus::NoArg,
            Some(s) => {
                let p = Path::new(&s);
                match p.exists() && p.is_file() {
                    true => CfgStatus::FileExists,
                    false => CfgStatus::FileNotExists,
                }
            }
        }
    }

    pub fn get_path(&self) -> Result<&Path, Box<dyn std::error::Error + Send + Sync>> {
        match &self.config_location {
            None => Err(Box::new(ArgError::NoPathProvided)),
            Some(s) => Ok(Path::new(s)),
        }
    }

    /// Consumes self and returns parts.
    /// In order, it returns:
    /// address, port, rl1_window, rl1_max, rl2_window, rl2_max, firewall_ban, config_location
    pub fn unravel(self) -> (String, u16, u64, u32, u64, u32, bool, Option<String>, String, String) {
        return (
            self.address,
            self.port,
            self.rl1_window,
            self.rl1_max,
            self.rl2_window,
            self.rl2_max,
            self.zzz_remove_me_firewall_ban,
            self.config_location,
            self.manifest_location,
            self.feature_extraction_script,
        );
    }
}
