// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::{ExecuteCommandResult, KamuNodePuppet};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
pub trait KamuNodePuppetExt {
    async fn assert_success_command_execution<I, S>(
        &self,
        cmd: I,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>;

    async fn assert_success_command_execution_with_input<I, S, T>(
        &self,
        cmd: I,
        input: T,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
        T: Into<Vec<u8>> + Send;

    async fn assert_success_command_execution_with_env<I, S>(
        &self,
        cmd: I,
        env_vars: Vec<(&std::ffi::OsStr, &std::ffi::OsStr)>,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>;

    async fn assert_failure_command_execution<I, S>(
        &self,
        cmd: I,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>;

    async fn assert_failure_command_execution_with_input<I, S, T>(
        &self,
        cmd: I,
        input: T,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
        T: Into<Vec<u8>> + Send;

    async fn complete<T>(&self, input: T, current: usize) -> Vec<String>
    where
        T: Into<String> + Send;

    async fn start_api_server(self, e2e_data_file_path: PathBuf) -> ServerOutput;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
impl KamuNodePuppetExt for KamuNodePuppet {
    async fn complete<T>(&self, input: T, current: usize) -> Vec<String>
    where
        T: Into<String> + Send,
    {
        let assert = self
            .execute([
                "complete",
                input.into().as_str(),
                current.to_string().as_str(),
            ])
            .await
            .success();

        let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();

        stdout.lines().map(ToString::to_string).collect()
    }

    async fn start_api_server(self, e2e_data_file_path: PathBuf) -> ServerOutput {
        let host = Ipv4Addr::LOCALHOST.to_string();

        let assert = self
            .execute([
                "--multi-tenant",
                "--e2e-output-data-path",
                e2e_data_file_path.to_str().unwrap(),
                "run",
                "--address",
                host.as_str(),
            ])
            .await
            .success();

        let stdout = std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .to_owned();
        let stderr = std::str::from_utf8(&assert.get_output().stderr)
            .unwrap()
            .to_owned();

        ServerOutput { stdout, stderr }
    }

    async fn assert_success_command_execution<I, S>(
        &self,
        cmd: I,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
    {
        assert_execute_command_result(
            &self.execute(cmd).await.success(),
            maybe_expected_stdout,
            maybe_expected_stderr,
        );
    }

    async fn assert_success_command_execution_with_input<I, S, T>(
        &self,
        cmd: I,
        input: T,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
        T: Into<Vec<u8>> + Send,
    {
        assert_execute_command_result(
            &self.execute_with_input(cmd, input).await.success(),
            maybe_expected_stdout,
            maybe_expected_stderr,
        );
    }

    async fn assert_success_command_execution_with_env<I, S>(
        &self,
        cmd: I,
        env_vars: Vec<(&std::ffi::OsStr, &std::ffi::OsStr)>,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
    {
        assert_execute_command_result(
            &self.execute_with_env(cmd, env_vars).await.success(),
            maybe_expected_stdout,
            maybe_expected_stderr,
        );
    }

    async fn assert_failure_command_execution<I, S>(
        &self,
        cmd: I,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
    {
        assert_execute_command_result(
            &self.execute(cmd).await.failure(),
            maybe_expected_stdout,
            maybe_expected_stderr,
        );
    }

    async fn assert_failure_command_execution_with_input<I, S, T>(
        &self,
        cmd: I,
        input: T,
        maybe_expected_stdout: Option<&str>,
        maybe_expected_stderr: Option<impl IntoIterator<Item = &str> + Send>,
    ) where
        I: IntoIterator<Item = S> + Send,
        S: AsRef<std::ffi::OsStr>,
        T: Into<Vec<u8>> + Send,
    {
        assert_execute_command_result(
            &self.execute_with_input(cmd, input).await.failure(),
            maybe_expected_stdout,
            maybe_expected_stderr,
        );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ServerOutput {
    pub stdout: String,
    pub stderr: String,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct DatasetRecord {
    #[serde(rename = "ID")]
    pub id: odf::DatasetID,
    pub name: odf::DatasetName,
    // CLI returns regular ENUM DatasetKind(Root/Derivative) for local datasets
    // but for remote it is Remote(DatasetKind) type
    pub kind: String,
    pub head: odf::Multihash,
    pub pulled: Option<DateTime<Utc>>,
    pub records: usize,
    pub blocks: usize,
    pub size: usize,
    pub watermark: Option<DateTime<Utc>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RepoAlias {
    pub dataset: odf::DatasetAlias,
    pub kind: String,
    pub alias: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlockRecord {
    pub block_hash: odf::Multihash,
    pub block: odf::MetadataBlock,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RepoRecord {
    pub name: odf::RepoName,
    pub url: url::Url,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

fn assert_execute_command_result<'a>(
    command_result: &ExecuteCommandResult,
    maybe_expected_stdout: Option<&str>,
    maybe_expected_stderr: Option<impl IntoIterator<Item = &'a str>>,
) {
    let actual_stdout = std::str::from_utf8(&command_result.get_output().stdout).unwrap();

    if let Some(expected_stdout) = maybe_expected_stdout {
        pretty_assertions::assert_eq!(expected_stdout, actual_stdout);
    }

    if let Some(expected_stderr_items) = maybe_expected_stderr {
        let stderr = std::str::from_utf8(&command_result.get_output().stderr).unwrap();

        for expected_stderr_item in expected_stderr_items {
            assert!(
                stderr.contains(expected_stderr_item),
                "Expected output:\n{expected_stderr_item}\nUnexpected output:\n{stderr}",
            );
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
