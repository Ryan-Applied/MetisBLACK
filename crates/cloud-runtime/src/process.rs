use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::catalogue::Operation;
use crate::error::{CloudError, Result};

#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Wrap an existing run-level cancellation flag so orchestrators and cloud
    /// subprocesses observe the same atomic state.
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableProbe {
    pub requested: String,
    pub resolved: PathBuf,
}

#[derive(Clone)]
pub struct CommandSpec {
    pub operation: Operation,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub timeout: Duration,
    pub output_cap_bytes: usize,
    pub cancellation: CancellationToken,
    environment: BTreeMap<String, String>,
}

impl CommandSpec {
    pub(crate) fn new(
        operation: Operation,
        executable: PathBuf,
        arguments: Vec<String>,
        environment: BTreeMap<String, String>,
        timeout: Duration,
        output_cap_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            operation,
            executable,
            arguments,
            timeout,
            output_cap_bytes,
            cancellation,
            environment,
        }
    }

    pub fn environment_names(&self) -> Vec<String> {
        self.environment.keys().cloned().collect()
    }

    pub(crate) fn environment(&self) -> impl Iterator<Item = (&str, &str)> {
        self.environment
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

impl Debug for CommandSpec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSpec")
            .field("operation", &self.operation)
            .field("executable", &self.executable)
            .field("arguments", &self.arguments)
            .field("timeout", &self.timeout)
            .field("output_cap_bytes", &self.output_cap_bytes)
            .field("environment_names", &self.environment_names())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub started_unix_ms: u128,
    pub duration: Duration,
    pub timed_out: bool,
    pub cancelled: bool,
}

impl ProcessOutput {
    pub fn success_json(value: impl Into<String>) -> Self {
        let stdout = value.into();
        Self {
            exit_code: Some(0),
            stdout_bytes: stdout.len(),
            stderr_bytes: 0,
            stdout,
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            started_unix_ms: 0,
            duration: Duration::ZERO,
            timed_out: false,
            cancelled: false,
        }
    }

    pub fn failed(exit_code: i32, stderr: impl Into<String>) -> Self {
        let stderr = stderr.into();
        Self {
            exit_code: Some(exit_code),
            stdout: String::new(),
            stderr_bytes: stderr.len(),
            stderr,
            stdout_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            started_unix_ms: 0,
            duration: Duration::ZERO,
            timed_out: false,
            cancelled: false,
        }
    }
}

pub trait CommandRunner: Send + Sync {
    fn discover(&self, executable: &str) -> Result<ExecutableProbe>;
    fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput>;
}

/// Direct-argv subprocess runner. It never invokes a shell.
#[derive(Debug, Clone)]
pub struct SystemRunner {
    search_paths: Vec<PathBuf>,
}

impl SystemRunner {
    pub fn from_current_path() -> Self {
        let search_paths = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        Self { search_paths }
    }

    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::from_current_path()
    }
}

impl CommandRunner for SystemRunner {
    fn discover(&self, executable: &str) -> Result<ExecutableProbe> {
        if executable.contains('/') || executable.contains('\\') || executable.is_empty() {
            return Err(CloudError::ExecutableNotFound(executable.into()));
        }
        for directory in &self.search_paths {
            let candidate = directory.join(executable);
            if is_executable_file(&candidate) {
                return Ok(ExecutableProbe {
                    requested: executable.into(),
                    resolved: candidate,
                });
            }
        }
        Err(CloudError::ExecutableNotFound(executable.into()))
    }

    fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput> {
        if !spec.executable.is_absolute() {
            return Err(CloudError::Process(
                "system runner requires a discovered absolute executable".into(),
            ));
        }
        let started_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let started = Instant::now();
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("AWS_PAGER", "")
            .env("AZURE_CORE_NO_COLOR", "true")
            .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in spec.environment() {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .map_err(|error| CloudError::Process(error.to_string()))?;
        let execution_started = Instant::now();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CloudError::Process("stdout capture unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CloudError::Process("stderr capture unavailable".into()))?;
        let cap = spec.output_cap_bytes;
        let stdout_reader = thread::spawn(move || read_capped(stdout, cap));
        let stderr_reader = thread::spawn(move || read_capped(stderr, cap));

        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            if spec.cancellation.is_cancelled() {
                cancelled = true;
                let _ = child.kill();
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if execution_started.elapsed() >= spec.timeout => {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait();
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => break Err(error),
            }
        }
        .map_err(|error| CloudError::Process(error.to_string()))?;
        let (stdout, stdout_bytes, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| CloudError::Process("stdout reader panicked".into()))??;
        let (stderr, stderr_bytes, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| CloudError::Process("stderr reader panicked".into()))??;
        Ok(ProcessOutput {
            exit_code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stdout_bytes,
            stderr_bytes,
            stdout_truncated,
            stderr_truncated,
            started_unix_ms,
            duration: started.elapsed(),
            timed_out,
            cancelled,
        })
    }
}

fn read_capped(mut reader: impl Read, cap: usize) -> Result<(Vec<u8>, usize, bool)> {
    let mut kept = Vec::with_capacity(cap.min(64 * 1024));
    let mut total = 0usize;
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| CloudError::Process(error.to_string()))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        let room = cap.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(room)]);
    }
    Ok((kept, total, total > cap))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[derive(Debug, Clone)]
pub struct MockCall {
    pub operation: Operation,
    pub output: ProcessOutput,
}

impl MockCall {
    pub fn json(operation: Operation, json: impl Into<String>) -> Self {
        Self {
            operation,
            output: ProcessOutput::success_json(json),
        }
    }

    pub fn failure(operation: Operation, exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            operation,
            output: ProcessOutput::failed(exit_code, stderr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCall {
    pub operation: Operation,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MockRunner {
    queued: Arc<Mutex<VecDeque<MockCall>>>,
    observed: Arc<Mutex<Vec<ObservedCall>>>,
}

impl MockRunner {
    pub fn new(calls: impl IntoIterator<Item = MockCall>) -> Self {
        Self {
            queued: Arc::new(Mutex::new(calls.into_iter().collect())),
            observed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn calls(&self) -> Vec<ObservedCall> {
        self.observed.lock().expect("mock lock poisoned").clone()
    }

    pub fn remaining(&self) -> usize {
        self.queued.lock().expect("mock lock poisoned").len()
    }
}

impl CommandRunner for MockRunner {
    fn discover(&self, executable: &str) -> Result<ExecutableProbe> {
        Ok(ExecutableProbe {
            requested: executable.into(),
            resolved: PathBuf::from(format!("/mock/bin/{executable}")),
        })
    }

    fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput> {
        self.observed
            .lock()
            .expect("mock lock poisoned")
            .push(ObservedCall {
                operation: spec.operation,
                executable: spec.executable.clone(),
                arguments: spec.arguments.clone(),
                environment_names: spec.environment_names(),
            });
        let call = self
            .queued
            .lock()
            .expect("mock lock poisoned")
            .pop_front()
            .ok_or_else(|| CloudError::Process("unexpected mock command".into()))?;
        if call.operation != spec.operation {
            return Err(CloudError::Process(format!(
                "expected {:?}, got {:?}",
                call.operation, spec.operation
            )));
        }
        Ok(call.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cancellation_token_observes_shared_orchestrator_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = CancellationToken::from_flag(Arc::clone(&flag));
        assert!(!token.is_cancelled());
        flag.store(true, Ordering::SeqCst);
        assert!(token.is_cancelled());
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_caps_output_and_uses_no_shell() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("fake-cloud");
        let shell_marker = directory.path().join("shell-was-invoked");
        fs::write(&executable, "#!/bin/sh\nprintf 1234567890\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let runner = SystemRunner::new(vec![directory.path().to_path_buf()]);
        let probe = runner.discover("fake-cloud").unwrap();
        let spec = CommandSpec::new(
            Operation::AwsVersion,
            probe.resolved,
            vec![
                "--version".into(),
                format!("; touch {}", shell_marker.display()),
            ],
            BTreeMap::new(),
            Duration::from_secs(30),
            4,
            CancellationToken::default(),
        );
        let output = runner.run(&spec).unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        assert_eq!(output.stdout, "1234");
        assert_eq!(output.stdout_bytes, 10);
        assert!(output.stdout_truncated);
        assert!(!shell_marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_enforces_timeout_and_cancellation() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("slow-cloud");
        fs::write(&executable, "#!/bin/sh\nexec sleep 5\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let runner = SystemRunner::new(vec![directory.path().to_path_buf()]);
        let probe = runner.discover("slow-cloud").unwrap();
        let timeout_spec = CommandSpec::new(
            Operation::AwsVersion,
            probe.resolved.clone(),
            vec!["--version".into()],
            BTreeMap::new(),
            Duration::from_millis(20),
            1024,
            CancellationToken::default(),
        );
        let timed_out = runner.run(&timeout_spec).unwrap();
        assert!(timed_out.timed_out);

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled_spec = CommandSpec::new(
            Operation::AwsVersion,
            probe.resolved,
            vec!["--version".into()],
            BTreeMap::new(),
            Duration::from_secs(2),
            1024,
            cancellation,
        );
        let cancelled = runner.run(&cancelled_spec).unwrap();
        assert!(cancelled.cancelled);
    }
}
