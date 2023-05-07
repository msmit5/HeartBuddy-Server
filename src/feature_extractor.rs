/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use std::fmt::Display;
use tokio::process::Command;
use std::error::Error as Std_Error;
use itertools::Itertools;
use tracing::{info, warn, error};

pub struct FeatureExtractor {
    process_spawn: String,
}

#[derive(Debug)]
pub enum FeatureExtractorError {
    FailedToRun(String),
}

impl Std_Error for FeatureExtractorError {}

impl Display for FeatureExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FeatureExtractorError::FailedToRun(s) => write!(f, "Failed to run! Reason:\n{s}"),
        }
    }
}

// TODO: Make sure the owner of the feature extractor is owned by the process, and it has 700 perms
// TODO: Take file hash and check to make sure that the feature extraction script has not changed
impl FeatureExtractor {
    pub fn new(proc: String) -> FeatureExtractor {
        FeatureExtractor { process_spawn: proc }
    }

    pub async fn run_process(&self, args: &str) -> Result<(), FeatureExtractorError> {
        let cmds = self.process_spawn.clone();
        let mut cmds = cmds
            .split(" ")
            .collect_vec();
        cmds.push(args);
        assert!(cmds.len() > 0);
        let fex = Command::new(cmds[0])
            .args(&cmds[1..])
            .output()
            .await
            .expect(&format!("Failed to run Feature Extraction process {}",self.process_spawn));

        let ret = fex.stdout;
        if ret.len() > 0 {
            info!("Output from script!\n{}", String::from_utf8(ret).unwrap());
        }
       
        let err = fex.stderr;
        if err.len() > 0 {
            warn!("Output from Feature Extractor contains stderr!");
            error!("{}", &String::from_utf8_lossy(&err));
        }

        if !std::path::Path::new(&format!("{args}.png")).exists() {
            return Err(FeatureExtractorError::FailedToRun(String::from_utf8_lossy(&err).to_string()));
        }
        return Ok(());
    }
}
