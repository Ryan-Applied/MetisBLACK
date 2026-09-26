use crate::CancellationToken;
use anyhow::{ensure, Context, Result};
use ring::digest::{digest, SHA256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    task::JoinHandle,
    time::{sleep, timeout},
};

const CHILD_REAP_GRACE: Duration = Duration::from_secs(1);
// Allow enough scheduler slack for heavily parallel CI while remaining
// strictly bounded when a descendant retains inherited pipe handles.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(10);

pub(crate) struct ProcessRequest {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub working_directory: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub timeout: Duration,
    pub stdout_cap: usize,
    pub stderr_cap: usize,
    pub cancellation: CancellationToken,
}

pub(crate) struct ProcessCapture {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub started_unix_ms: u64,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub cancelled: bool,
    pub output_overflowed: bool,
    pub direct_child_termination_attempted: bool,
    pub direct_child_reaped: bool,
    pub pipe_drain_aborted: bool,
    pub stdin_write_aborted: bool,
    pub io_error: Option<String>,
}

impl ProcessCapture {
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub(crate) fn resolve_executable(configured: Option<&Path>, default_name: &str) -> Result<PathBuf> {
    let candidate = if let Some(path) = configured {
        ensure!(
            path.is_absolute(),
            "configured subscription CLI executable must be absolute"
        );
        path.to_owned()
    } else {
        ensure!(
            !default_name.contains('/') && !default_name.contains('\\'),
            "invalid subscription CLI executable name"
        );
        let path = std::env::var_os("PATH").context("PATH is unavailable for CLI discovery")?;
        std::env::split_paths(&path)
            .map(|directory| directory.join(default_name))
            .find(|candidate| executable_file(candidate))
            .with_context(|| format!("subscription CLI {default_name} was not found"))?
    };
    let canonical = std::fs::canonicalize(&candidate)
        .with_context(|| format!("failed to resolve subscription CLI {}", candidate.display()))?;
    ensure!(
        canonical.is_absolute(),
        "resolved subscription CLI path is not absolute"
    );
    ensure!(
        executable_file(&canonical),
        "subscription CLI is not an executable file"
    );
    Ok(canonical)
}

pub(crate) async fn run_process(request: ProcessRequest) -> Result<ProcessCapture> {
    ensure!(
        request.executable.is_absolute(),
        "process executable must be absolute"
    );
    ensure!(
        !request.timeout.is_zero(),
        "process timeout must be positive"
    );
    ensure!(
        request.stdout_cap > 0 && request.stderr_cap > 0,
        "process caps must be positive"
    );
    ensure!(
        !request.cancellation.is_cancelled(),
        "provider invocation cancelled"
    );

    let started_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )?;
    let started = Instant::now();
    let mut command = Command::new(&request.executable);
    command
        .args(&request.arguments)
        .env_clear()
        .envs(&request.environment)
        .stdin(if request.stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(directory) = &request.working_directory {
        command.current_dir(directory);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", request.executable.display()))?;
    let execution_started = Instant::now();
    let stdout = child
        .stdout
        .take()
        .context("subscription CLI stdout was unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("subscription CLI stderr was unavailable")?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_capture = Arc::new(Mutex::new(CappedBytes::new(request.stdout_cap)));
    let stderr_capture = Arc::new(Mutex::new(CappedBytes::new(request.stderr_cap)));
    let stdout_reader = tokio::spawn(read_capped(
        stdout,
        stdout_capture.clone(),
        overflow.clone(),
    ));
    let stderr_reader = tokio::spawn(read_capped(
        stderr,
        stderr_capture.clone(),
        overflow.clone(),
    ));
    let stdin_writer = if let Some(input) = request.stdin {
        let mut stdin = child
            .stdin
            .take()
            .context("subscription CLI stdin was unavailable")?;
        Some(tokio::spawn(async move {
            let result = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
            result
        }))
    } else {
        None
    };

    let mut timed_out = false;
    let mut cancelled = false;
    let mut output_overflowed = false;
    let mut direct_child_termination_attempted = false;
    let mut wait_error = None;
    let mut status = loop {
        if request.cancellation.is_cancelled() {
            cancelled = true;
            direct_child_termination_attempted = true;
            let _ = child.start_kill();
            break None;
        }
        if overflow.load(Ordering::SeqCst) {
            output_overflowed = true;
            direct_child_termination_attempted = true;
            let _ = child.start_kill();
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if execution_started.elapsed() >= request.timeout => {
                timed_out = true;
                direct_child_termination_attempted = true;
                let _ = child.start_kill();
                break None;
            }
            Ok(None) => sleep(Duration::from_millis(10)).await,
            Err(error) => {
                direct_child_termination_attempted = true;
                let _ = child.start_kill();
                wait_error = Some(format!(
                    "failed while waiting for subscription CLI: {error}"
                ));
                break None;
            }
        }
    };

    if status.is_none() {
        status = timeout(CHILD_REAP_GRACE, child.wait())
            .await
            .ok()
            .and_then(Result::ok);
    }
    let direct_child_reaped = status.is_some();

    let mut stdin_write_aborted = false;
    if let Some(mut writer) = stdin_writer {
        // BrokenPipe is expected when a child rejects the invocation before it
        // consumes stdin; the exit status and stderr are the authoritative error.
        if timeout(PIPE_DRAIN_GRACE, &mut writer).await.is_err() {
            stdin_write_aborted = true;
            writer.abort();
            let _ = writer.await;
        }
    }
    let (stdout_drain, stderr_drain) =
        tokio::join!(finish_reader(stdout_reader), finish_reader(stderr_reader));
    let pipe_drain_aborted = stdout_drain.aborted || stderr_drain.aborted;
    let io_error = [wait_error, stdout_drain.error, stderr_drain.error]
        .into_iter()
        .flatten()
        .next();
    let stdout = snapshot(&stdout_capture);
    let stderr = snapshot(&stderr_capture);
    Ok(ProcessCapture {
        exit_code: status.and_then(|status| status.code()),
        stdout: stdout.kept,
        stderr: stderr.kept,
        stdout_bytes: stdout.total,
        stderr_bytes: stderr.total,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        started_unix_ms,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        timed_out,
        cancelled,
        output_overflowed,
        direct_child_termination_attempted,
        direct_child_reaped,
        pipe_drain_aborted,
        stdin_write_aborted,
        io_error,
    })
}

#[derive(Clone)]
struct CappedBytes {
    kept: Vec<u8>,
    total: u64,
    truncated: bool,
    cap: usize,
}

impl CappedBytes {
    fn new(cap: usize) -> Self {
        Self {
            kept: Vec::with_capacity(cap.min(64 * 1024)),
            total: 0,
            truncated: false,
            cap,
        }
    }
}

async fn read_capped(
    mut reader: impl AsyncRead + Unpin,
    capture: Arc<Mutex<CappedBytes>>,
    overflow: Arc<AtomicBool>,
) -> Result<()> {
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .context("failed reading child output")?;
        if read == 0 {
            break;
        }
        let mut state = capture
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.total = state.total.saturating_add(u64::try_from(read)?);
        let remaining = state.cap.saturating_sub(state.kept.len());
        state.kept.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining {
            state.truncated = true;
            overflow.store(true, Ordering::SeqCst);
        }
    }
    Ok(())
}

struct ReaderDrain {
    aborted: bool,
    error: Option<String>,
}

async fn finish_reader(mut reader: JoinHandle<Result<()>>) -> ReaderDrain {
    match timeout(PIPE_DRAIN_GRACE, &mut reader).await {
        Ok(Ok(Ok(()))) => ReaderDrain {
            aborted: false,
            error: None,
        },
        Ok(Ok(Err(error))) => ReaderDrain {
            aborted: false,
            error: Some(error.to_string()),
        },
        Ok(Err(error)) => ReaderDrain {
            aborted: false,
            error: Some(format!("output reader task failed: {error}")),
        },
        Err(_) => {
            // Prefer an output reader that completed at the deadline boundary.
            // A heavily loaded executor can wake the timeout before polling an
            // already-readable EOF; one scheduler yield distinguishes that
            // case from a descendant that still owns the pipe.
            tokio::task::yield_now().await;
            if reader.is_finished() {
                return match reader.await {
                    Ok(Ok(())) => ReaderDrain {
                        aborted: false,
                        error: None,
                    },
                    Ok(Err(error)) => ReaderDrain {
                        aborted: false,
                        error: Some(error.to_string()),
                    },
                    Err(error) => ReaderDrain {
                        aborted: false,
                        error: Some(format!("output reader task failed: {error}")),
                    },
                };
            }
            reader.abort();
            // Await cancellation so the pipe handle is definitely dropped;
            // merely requesting abort can leave the read future alive until a
            // later scheduler turn while a descendant keeps the writer open.
            let _ = reader.await;
            ReaderDrain {
                aborted: true,
                error: None,
            }
        }
    }
}

fn snapshot(capture: &Arc<Mutex<CappedBytes>>) -> CappedBytes {
    capture
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
