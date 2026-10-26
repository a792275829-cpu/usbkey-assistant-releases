//! Only the configured FT3000GM helpers can be launched; this is not a shell RPC.
use crate::pin_session::Session;
use anyhow::{Result, bail};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{mpsc, watch},
};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    tool: String,
    args: Vec<String>,
    #[serde(default)]
    input: String,
    #[serde(default, rename = "authToken")]
    auth_token: Option<u64>,
}

impl Drop for Request {
    fn drop(&mut self) {
        self.input.zeroize();
    }
}

pub struct Job {
    pub id: u64,
    pub request: Request,
}

pub struct Helpers {
    pub probe: PathBuf,
    pub signer: PathBuf,
}

struct Policy {
    deadline: Duration,
    stdout_limit: usize,
}

impl Request {
    fn policy(&self) -> Result<Policy> {
        if self.tool == "prompt" {
            if !self.args.is_empty() || !self.input.is_empty() {
                bail!("invalid_request");
            }
            return Ok(Policy {
                deadline: Duration::from_secs(120),
                stdout_limit: 4096,
            });
        }
        let operation = self.args.first().map(String::as_str).unwrap_or("");
        let readonly = match (self.tool.as_str(), operation) {
            ("probe", "--list-devices" | "--include-certificate") => true,
            ("signer", "--pin-status") => true,
            (
                "signer",
                "--sign-digest-info" | "--decrypt-rsa-block" | "--decrypt-rsa-block-no-pin",
            ) => false,
            _ => bail!("invalid_request"),
        };
        if self.args.len() != 1 && self.args.len() != 3 {
            bail!("invalid_request");
        }
        if self.args.len() == 3 {
            let device = &self.args[2];
            if self.args[1] != "--device-id"
                || device.len() > 16
                || device.is_empty()
                || !device.bytes().all(|b| b.is_ascii_hexdigit())
                || u64::from_str_radix(device, 16).unwrap_or(0) == 0
            {
                bail!("invalid_request");
            }
        }
        if operation == "--list-devices" && self.args.len() != 1 {
            bail!("invalid_request");
        }
        if readonly {
            if !self.input.is_empty() {
                bail!("invalid_request");
            }
        } else {
            if self.input.len() > 4096 || self.input.contains(['\r', '\0']) {
                bail!("invalid_request");
            }
            let text = self
                .input
                .strip_suffix('\n')
                .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
            let data = if operation == "--decrypt-rsa-block-no-pin" {
                text
            } else {
                let (pin, data) = text
                    .split_once('\n')
                    .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
                if pin.is_empty() || pin.len() > 64 {
                    bail!("invalid_request");
                }
                data
            };
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|_| anyhow::anyhow!("invalid_request"))?;
            if bytes.is_empty() || bytes.len() > 1024 {
                bail!("invalid_request");
            }
            if operation.starts_with("--decrypt-rsa-block") && bytes.len() != 256 {
                bail!("invalid_request");
            }
        }
        Ok(Policy {
            deadline: Duration::from_secs(if readonly { 10 } else { 15 }),
            stdout_limit: if operation == "--pin-status" {
                65536
            } else {
                1024 * 1024
            },
        })
    }
}

// Each helper owns a process group. Closing the bridge also terminates a helper
// whose descendant retained a pipe; never leave an orphan accessing the token.
// The guard is disarmed once the helper has been reaped: at that point the pid
// (and therefore the pgid) may already belong to an unrelated process.
struct ProcessGroup {
    pgid: i32,
    armed: bool,
}
impl ProcessGroup {
    fn new(pid: u32) -> Self {
        Self {
            pgid: -(pid as i32),
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(self.pgid, libc::SIGKILL);
            }
        }
    }
}

async fn read_output(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    (&mut reader)
        .take((limit + 1) as u64)
        .read_to_end(&mut output)
        .await
        .map_err(|_| anyhow::anyhow!("io_failed"))?;
    if output.len() > limit {
        output.zeroize();
        bail!("output_limit");
    }
    Ok(output)
}

async fn execute(
    request: &Request,
    helpers: &Helpers,
    policy: Policy,
    stop: &mut watch::Receiver<bool>,
    authentication: Option<&Arc<Mutex<Session>>>,
) -> Result<Value> {
    let path = if request.tool == "prompt" {
        std::path::Path::new("/usr/bin/osascript")
    } else if request.tool == "probe" {
        helpers.probe.as_path()
    } else {
        helpers.signer.as_path()
    };
    let mut command = Command::new(path);
    if request.tool == "prompt" {
        command.args(["-e", "text returned of (display dialog \"请输入 USBKey 证书密码以完成本次操作\" default answer \"\" with hidden answer buttons {\"取消\", \"确认\"} default button \"确认\" cancel button \"取消\" with title \"广东电力USBKey助手\")"]);
    } else {
        command.args(&request.args);
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    // The hardware helpers need no home directory; the dialog does, and it is
    // the only helper that talks to AppKit.
    if request.tool == "prompt"
        && let Ok(home) = std::env::var("HOME")
    {
        command.env("HOME", home);
    }
    let mut child = {
        let mut session = authentication.map(|s| s.lock().unwrap());
        if request.tool == "signer"
            && request.args[0] != "--pin-status"
            && let Some(session) = &mut session
        {
            let pin = if request.args[0] == "--decrypt-rsa-block-no-pin" {
                None
            } else {
                request.input.split_once('\n').map(|v| v.0)
            };
            session
                .authorize_hardware(
                    request.auth_token.unwrap_or(0),
                    request.args.get(2).map(String::as_str),
                    pin,
                )
                .map_err(|_| anyhow::anyhow!("auth_stale"))?;
        }
        command
            .spawn()
            .map_err(|_| anyhow::anyhow!("spawn_failed"))?
    };
    let mut group = ProcessGroup::new(child.id().unwrap());
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let operation = async {
        let write = async {
            // Early device failure can close stdin before consuming the PIN.
            // Still collect its JSON/status rather than replacing the error.
            if let Err(error) = stdin.write_all(request.input.as_bytes()).await
                && error.kind() != std::io::ErrorKind::BrokenPipe
            {
                bail!("io_failed");
            }
            drop(stdin);
            Ok(())
        };
        let ((), stdout, mut stderr, status) = tokio::try_join!(
            write,
            read_output(stdout, policy.stdout_limit),
            read_output(stderr, 65536),
            async { child.wait().await.map_err(|_| anyhow::anyhow!("io_failed")) }
        )?;
        let stderr_bytes = stderr.len();
        stderr.zeroize();
        let stdout = String::from_utf8(stdout).map_err(|_| anyhow::anyhow!("invalid_output"))?;
        Ok(json!({"code": status.code(), "stdout": stdout, "stderrBytes": stderr_bytes}))
    };
    let result = tokio::select! {
        biased;
        _ = stop.changed() => Err(anyhow::anyhow!("cancelled")),
        result = tokio::time::timeout(policy.deadline, operation) =>
            result.unwrap_or_else(|_| Err(anyhow::anyhow!("timeout"))),
    };
    // A normally finished helper was reaped by `wait()` above, so its pid (and
    // therefore its process group id) may already belong to another process;
    // only a failed run still needs the whole group killed. The group is killed
    // before `child.kill()` so a descendant holding a pipe cannot stall it.
    if result.is_ok() {
        group.disarm();
    }
    drop(group);
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

pub async fn supervise(
    mut jobs: mpsc::Receiver<Job>,
    replies: mpsc::Sender<Value>,
    helpers: Helpers,
    mut stop: watch::Receiver<bool>,
    shutdown: watch::Sender<bool>,
    authentication: Arc<Mutex<Session>>,
) -> Result<()> {
    loop {
        let job = tokio::select! {
            biased;
            _ = stop.changed() => break,
            job = jobs.recv() => match job { Some(job) => job, None => break },
        };
        if *stop.borrow() {
            break;
        }
        let result = match job.request.policy() {
            Ok(policy) => {
                execute(
                    &job.request,
                    &helpers,
                    policy,
                    &mut stop,
                    Some(&authentication),
                )
                .await
            }
            Err(error) => Err(error),
        };
        if *stop.borrow() {
            break;
        }
        let reply = match result {
            Ok(result) => json!({"helperId": job.id, "result": result}),
            // Only fixed error identifiers cross IPC; never include command,
            // input, helper output, or environment in diagnostics.
            Err(error) => json!({"helperId": job.id, "error": error.to_string()}),
        };
        if replies.try_send(reply).is_err() {
            let _ = shutdown.send(true);
            bail!("cannot deliver helper result");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(body: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "usbkey-process-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            let script = dir.join("helper");
            fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            Self(dir)
        }
        fn helpers(&self) -> Helpers {
            Helpers {
                probe: self.0.join("helper"),
                signer: self.0.join("helper"),
            }
        }
        fn pid_file(&self) -> String {
            self.0.join("pid").to_string_lossy().into_owned()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn probe() -> Request {
        Request {
            tool: "probe".into(),
            args: vec!["--list-devices".into()],
            input: String::new(),
            auth_token: None,
        }
    }
    fn normal_policy() -> Policy {
        probe().policy().unwrap()
    }
    async fn run(fixture: &Fixture) -> Result<Value> {
        let (_stop, mut stopped) = watch::channel(false);
        execute(
            &probe(),
            &fixture.helpers(),
            normal_policy(),
            &mut stopped,
            None,
        )
        .await
    }
    fn assert_reaped(fixture: &Fixture) {
        let pid: i32 = fs::read_to_string(fixture.pid_file())
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "helper is still alive or unreaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn validates_fixed_operations_and_stdin_before_launch() {
        for (tool, args, input) in [
            ("/bin/sh", vec!["--list-devices"], ""),
            ("probe", vec!["--list-devices", "--device-id", "a1"], ""),
            ("signer", vec!["--pin-status", "--device-id", "0"], ""),
            (
                "signer",
                vec!["--pin-status", "--device-id", "a1", "--status"],
                "",
            ),
            ("signer", vec!["--sign-digest-info"], "pin\nextra\nZA==\n"),
            ("signer", vec!["--decrypt-rsa-block-no-pin"], "ZA==\n"),
        ] {
            let request = Request {
                tool: tool.into(),
                args: args.into_iter().map(String::from).collect(),
                input: input.into(),
                auth_token: None,
            };
            assert!(request.policy().is_err());
        }
        let request = Request {
            tool: "signer".into(),
            args: vec![
                "--sign-digest-info".into(),
                "--device-id".into(),
                "a1".into(),
            ],
            input: "pin\nZA==\n".into(),
            auth_token: None,
        };
        assert!(request.policy().is_ok());
    }

    #[tokio::test]
    async fn drains_both_pipes_without_logging_stderr() {
        let fixture = Fixture::new(
            "/bin/dd if=/dev/zero bs=48000 count=1 >&2 2>/dev/null\n/bin/dd if=/dev/zero bs=800000 count=1 2>/dev/null",
        );
        let result = run(&fixture).await.unwrap();
        assert_eq!(result["code"], 0);
        assert_eq!(result["stdout"].as_str().unwrap().len(), 800000);
        assert_eq!(result["stderrBytes"], 48000);
        assert!(result.get("stderr").is_none());
    }

    #[tokio::test]
    async fn preserves_nonzero_business_result_without_retry() {
        let fixture = Fixture::new(
            "printf '%s\\n' '{\"pin_verified\":false,\"verify_sw\":\"63C2\",\"retries\":2}'\nexit 4",
        );
        let result = run(&fixture).await.unwrap();
        assert_eq!(result["code"], 4);
        assert!(result["stdout"].as_str().unwrap().contains("63C2"));
    }

    #[tokio::test]
    async fn rejects_stdout_and_stderr_overflow_and_reaps() {
        for (fd, size) in [(1, 1024 * 1024 + 1), (2, 65537)] {
            let fixture = Fixture::new("");
            fs::write(fixture.0.join("helper"), format!("#!/bin/sh\nprintf '%s' $$ > {:?}\n/bin/dd if=/dev/zero bs={size} count=1 >&{fd} 2>/dev/null\nexec /bin/sleep 30\n", fixture.pid_file())).unwrap();
            assert_eq!(run(&fixture).await.unwrap_err().to_string(), "output_limit");
            assert_reaped(&fixture);
        }
    }

    #[tokio::test]
    async fn deadline_kills_and_waits_for_helper() {
        let fixture = Fixture::new("");
        fs::write(
            fixture.0.join("helper"),
            format!(
                "#!/bin/sh\nprintf '%s' $$ > {:?}\nexec /bin/sleep 30\n",
                fixture.pid_file()
            ),
        )
        .unwrap();
        let (_stop, mut stopped) = watch::channel(false);
        let result = execute(
            &probe(),
            &fixture.helpers(),
            Policy {
                deadline: Duration::from_secs(3),
                ..normal_policy()
            },
            &mut stopped,
            None,
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "timeout");
        assert_reaped(&fixture);
    }

    #[tokio::test]
    async fn disarmed_group_leaves_a_live_process_alone() {
        // After a normal exit the helper's pid may already belong to someone
        // else; the guard must not signal it. An armed guard still cleans up.
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        {
            let mut group = ProcessGroup::new(pid);
            group.disarm();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            child.try_wait().unwrap().is_none(),
            "a disarmed guard must not kill the process"
        );
        drop(ProcessGroup::new(pid));
        let _ = child.wait().await;
        assert!(child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn shutdown_cancels_active_helper_and_reaps() {
        let fixture = Fixture::new("");
        fs::write(
            fixture.0.join("helper"),
            format!(
                "#!/bin/sh\nprintf '%s' $$ > {:?}\nexec /bin/sleep 30\n",
                fixture.pid_file()
            ),
        )
        .unwrap();
        let (stop, mut stopped) = watch::channel(false);
        let signal = async {
            while !fixture.0.join("pid").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            stop.send(true).unwrap();
        };
        let operation = async {
            execute(
                &probe(),
                &fixture.helpers(),
                normal_policy(),
                &mut stopped,
                None,
            )
            .await
        };
        let (result, ()) = tokio::join!(operation, signal);
        assert_eq!(result.unwrap_err().to_string(), "cancelled");
        assert_reaped(&fixture);
    }

    #[tokio::test]
    async fn spawn_and_encoding_failures_are_fixed_identifiers() {
        let fixture = Fixture::new("printf '\\377'");
        assert_eq!(
            run(&fixture).await.unwrap_err().to_string(),
            "invalid_output"
        );
        fs::remove_file(fixture.0.join("helper")).unwrap();
        assert_eq!(run(&fixture).await.unwrap_err().to_string(), "spawn_failed");
    }

    #[tokio::test]
    async fn supervisor_serializes_jobs_and_recovers_after_failure() {
        let fixture = Fixture::new("");
        let marker = fixture.0.join("calls");
        fs::write(fixture.0.join("helper"), format!("#!/bin/sh\nprintf 'start\\n' >> {marker:?}\n/bin/sleep .03\nprintf 'end\\n' >> {marker:?}\nprintf '%s\\n' '{{\"devices\":[]}}'\n")).unwrap();
        let (jobs, receiver) = mpsc::channel(4);
        let (replies, mut received) = mpsc::channel(4);
        let (stop, stopped) = watch::channel(false);
        let (shutdown, _) = watch::channel(false);
        let task = tokio::spawn(supervise(
            receiver,
            replies,
            fixture.helpers(),
            stopped,
            shutdown,
            Arc::new(Mutex::new(Session::default())),
        ));
        let mut invalid = probe();
        invalid.tool = "invalid".into();
        jobs.send(Job {
            id: 1,
            request: invalid,
        })
        .await
        .unwrap();
        for id in [2, 3] {
            jobs.send(Job {
                id,
                request: probe(),
            })
            .await
            .unwrap();
        }
        assert_eq!(received.recv().await.unwrap()["error"], "invalid_request");
        for id in [2, 3] {
            let reply = received.recv().await.unwrap();
            assert_eq!(reply["helperId"], id);
            assert_eq!(reply["result"]["code"], 0);
        }
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(marker).unwrap(),
            "start\nend\nstart\nend\n"
        );
    }
}
