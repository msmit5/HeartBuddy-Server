/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use clap::Parser;
use tracing_subscriber;

use std::error::Error as Std_Error;
mod args;
mod ml_controller;
mod ratelimit;
mod server;
mod feature_extractor;

#[tokio::main(worker_threads = 25)]
async fn main() -> Result<(), server::HBServerError> {
    //console_subscriber::init();
    let args = args::Args::parse();
    tracing_subscriber::fmt::init();

    // TODO: Refactor to print error messages properly!
    let cfg = server::Config::from_args(args)?;
    server::run(cfg).await
}
