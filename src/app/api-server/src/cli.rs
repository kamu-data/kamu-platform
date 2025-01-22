// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

use std::path::PathBuf;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, clap::Parser)]
#[command(name = crate::BINARY_NAME)]
#[command(version = crate::VERSION)]
#[command(after_help = r#"
To get help for individual commands use:
    kamu <command> -h
    kamu <command> <sub-command> -h
"#)]
pub struct Cli {
    /// Path to the config file
    #[arg(long, default_value = "config.yaml")]
    pub config: Option<PathBuf>,

    // TODO: This is temporary and will be removed soon
    // See: https://github.com/kamu-data/kamu-cli/issues/342
    /// Indicates that target repo is multi-tenant (for file:// only)
    #[arg(long)]
    pub multi_tenant: bool,

    /// E2E test interface: file path from which socket bound address will be
    /// read out
    #[arg(long, hide = true)]
    pub e2e_output_data_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    Run(Run),
    Gql(GqlGroup),
    Metrics(Metrics),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Run the server
#[derive(Debug, clap::Args)]
pub struct Run {
    /// Expose HTTP server on specific network interface
    #[arg(long)]
    pub address: Option<std::net::IpAddr>,

    /// Expose HTTP server on specific port
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Expose Flight SQL server on specific port
    #[arg(long)]
    pub flightsql_port: Option<u16>,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// GraphQL related command group
#[derive(Debug, clap::Args)]
pub struct GqlGroup {
    #[command(subcommand)]
    pub subcommand: Gql,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, clap::Subcommand)]
pub enum Gql {
    Schema(GqlSchema),
    Query(GqlQuery),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Prints out GraphQL schema
#[derive(Debug, clap::Args)]
pub struct GqlSchema {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Executes the GraphQL query and prints out the result
#[derive(Debug, clap::Args)]
#[command(after_help = r#"
Example:
    kamu-api-server gql query '{ apiVersion }'
"#)]
pub struct GqlQuery {
    /// Display the full result including extensions
    #[arg(long)]
    pub full: bool,

    /// GQL query
    #[arg(index = 1)]
    pub query: String,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Prints out GraphQL schema
#[derive(Debug, clap::Args)]
pub struct Metrics {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
