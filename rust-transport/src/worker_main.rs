use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::{mpsc, oneshot},
};
use zeroize::{Zeroize, Zeroizing};

#[path = "native/auth.rs"]
mod auth;
#[path = "native/certificates.rs"]
mod certificates;
#[path = "native/crypto.rs"]
mod crypto;
#[path = "native/rpc.rs"]
mod rpc;

type Slots = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;
/// Wire version reported to the local page and to the website RPC envelope.
///
/// This is deliberately frozen and **not** `CFBundleShortVersionString`: the
/// service compares it against a list the website knows about, so raising it
/// here without a matching change on the site can make the page reject the
/// bridge. Only change it together with that deployment.
const VERSION: &str = "1.1.15";
const MAX: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct Client {
    tx: mpsc::Sender<Value>,
    slots: Slots,
    sequence: Arc<AtomicU64>,
    keychain_slots: Slots,
    keychain: Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
    pub log: PathBuf,
    // One append handle for the process lifetime: `audit` runs on every request
    // and reopening plus chmod-ing the file each time is pure overhead.
    audit_file: Arc<Mutex<Option<std::fs::File>>>,
}
struct SlotGuard(u64, Slots);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.1.lock().unwrap().remove(&self.0);
    }
}
impl Client {
    pub fn send(&self, value: Value) -> Result<()> {
        self.tx
            .try_send(value)
            .map_err(|_| anyhow::anyhow!("私有通道已关闭或繁忙"))
    }
    async fn call(&self, channel: &str, request: Value) -> Result<Value> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut slots = self.slots.lock().unwrap();
            ensure!(slots.len() < 64, "内部请求过多");
            slots.insert(id, tx);
        }
        let _guard = SlotGuard(id, self.slots.clone());
        let mut value = json!({"request":request});
        value[channel] = json!(id);
        self.send(value)?;
        let mut value = rx.await.map_err(|_| anyhow::anyhow!("私有通道已关闭"))?;
        if let Some(error) = value["error"].as_str() {
            bail!(
                "{}",
                match error {
                    "stale" | "auth_stale" => "USBKey 状态已改变，请重新操作",
                    "invalid_pin" => "证书密码格式无效",
                    "timeout" => "USBKey 硬件操作超时",
                    "output_limit" => "USBKey 硬件助手输出超限",
                    "spawn_failed" => "无法启动 FT3000GM 硬件助手",
                    _ => "USBKey 内部操作失败",
                }
            );
        }
        Ok(value["result"].take())
    }
    pub async fn state(&self, request: Value) -> Result<Value> {
        self.call("pinId", request).await
    }
    pub async fn helper(
        &self,
        tool: &str,
        args: &[String],
        input: &str,
        token: Option<u64>,
    ) -> Result<Value> {
        self.call(
            "helperId",
            json!({"tool":tool,"args":args,"input":input,"authToken":token}),
        )
        .await
    }
    pub fn audit(&self, event: &str, details: Value) {
        // Call sites pass only explicit metadata. Never serialize requests/errors.
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut value = details;
        value["event"] = json!(event);
        value["timestamp"] = json!(chrono::Utc::now().to_rfc3339());
        let mut handle = self.audit_file.lock().unwrap();
        if handle.is_none() {
            if let Some(parent) = self.log.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let opened = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(&self.log)
                .inspect(|file| {
                    // `mode` only applies on creation; a pre-existing file keeps
                    // whatever it had, so tighten it once per process.
                    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
                });
            match opened {
                Ok(file) => *handle = Some(file),
                Err(_) => return,
            }
        }
        let Some(file) = handle.as_mut() else {
            return;
        };
        // A failed write (closed descriptor, full disk) drops the handle so the
        // next call reopens the path instead of retrying a dead one forever.
        if writeln!(file, "{value}").is_err() {
            *handle = None;
        }
    }

    /// Diagnostics switch for rejected `SignedDataSelect` requests, documented in
    /// `docs/RUST_TRANSPORT.md`. It is inert unless somebody deliberately creates
    /// `<log dir>/.capture-certificate-selector-once`, writes only the `type` and
    /// `condition` strings (capped at 4 KiB each, never certificate content), and
    /// consumes the marker so it captures a single request.
    pub fn capture_selector(&self, selector: &Value) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = self
            .log
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let marker = directory.join(".capture-certificate-selector-once");
        if !marker.exists() {
            return;
        }
        let mut rules = json!({});
        for key in ["type", "condition"] {
            let value = &selector[key];
            rules[key] = if value.as_str().is_some_and(|s| s.len() <= 4096) {
                value.clone()
            } else {
                json!({"type":if value.is_null(){"undefined"}else if value.is_string(){"string"}else{"object"},"length":value.as_str().map(str::len)})
            };
        }
        let path = directory.join("rejected-certificate-selector.json");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
        {
            let _ = writeln!(
                file,
                "{}",
                json!({"timestamp":chrono::Utc::now().to_rfc3339(),"rules":rules})
            );
        }
        let _ = std::fs::remove_file(marker);
    }
    pub async fn store(&self, operation: &str, binding: &str, pin: Option<&str>) -> Result<Value> {
        ensure!(
            std::env::var("USBKEY_PRIVATE_PIN_CHANNEL").as_deref() == Ok("1"),
            "钥匙串通道未连接"
        );
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut slots = self.keychain_slots.lock().unwrap();
            ensure!(slots.len() < 64, "钥匙串请求过多");
            slots.insert(id, tx);
        }
        let _guard = SlotGuard(id, self.keychain_slots.clone());
        let mut value =
            json!({"privateChannel":"pin-store-v1","requestId":id,"operation":operation});
        if operation != "clear" {
            let certs = binding.split_once(':').map(|v| v.1).unwrap_or("");
            ensure!(
                certs.len() == 64 && certs.bytes().all(|b| b.is_ascii_hexdigit()),
                "证书密码绑定无效"
            );
            value["account"] = json!(
                crypto::hex(&crypto::digest(
                    format!("certificate-set-v1:{}", certs.to_uppercase()).as_bytes(),
                    false
                ))
                .to_lowercase()
            );
        }
        if let Some(pin) = pin {
            value["pin"] = json!(pin);
        }
        let mut bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        wipe(&mut value);
        bytes.push(b'\n');
        self.keychain.lock().await.write_all(&bytes).await?;
        let reply = tokio::time::timeout(Duration::from_secs(120), rx).await??;
        ensure!(
            [0, -25300].contains(&reply["status"].as_i64().unwrap_or(1)),
            "钥匙串操作失败"
        );
        Ok(reply)
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

pub struct Connection {
    pub closed: AtomicBool,
    pub subscription: Mutex<Option<(Value, f64)>>,
    generation: AtomicU64,
}
pub type Connections = Arc<Mutex<HashMap<u64, Arc<Connection>>>>;
pub struct Job {
    id: u64,
    kind: String,
    connection: Option<(u64, Arc<Connection>)>,
    body: Value,
}
pub fn success(request: &Value, entity: Value) -> Value {
    envelope(request, entity, 0, "成功")
}
pub fn failure(request: &Value, message: &str, status: i64) -> Value {
    envelope(request, json!({}), status, message)
}
fn envelope(request: &Value, entity: Value, status: i64, message: &str) -> Value {
    let mut value = json!({"responseVersion":1,"requestVersion":request.get("requestVersion").filter(|v|!v.is_null()).cloned().unwrap_or(json!(1)),"responseResult":{"status":status,"msg":message},"responseEntity":entity});
    for k in ["lwsObjectId", "requestOrigin", "requestId"] {
        if let Some(v) = request.get(k) {
            value[k] = v.clone();
        }
    }
    value
}
pub fn notify(client: &Client, connections: &Connections, device: &Value, pull_out: bool) {
    for (id, connection) in connections.lock().unwrap().iter() {
        let sub = connection.subscription.lock().unwrap().clone();
        if let Some((request, delay)) = sub {
            let response = success(
                &request,
                json!({"type":device.get("device_type").cloned().unwrap_or(json!(47)),"sn":device["device_sn"].as_str().unwrap_or(""),"pullOut":pull_out,"deviceId":device["device_id"]}),
            );
            let client = client.clone();
            let connection = connection.clone();
            let id = *id;
            let epoch = connection.generation.load(Ordering::Relaxed);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                if !connection.closed.load(Ordering::Relaxed)
                    && connection.generation.load(Ordering::Relaxed) == epoch
                    && client
                        .send(json!({"connection":id,"response":response}))
                        .is_err()
                {
                    std::process::exit(1);
                }
            });
        }
    }
}

/// fd 3 is the private IPC channel created by the parent. If the parent passed
/// something else (or nothing), every later read would fail with an opaque
/// "Bad file descriptor"; fail once, with a comprehensible reason.
fn validate_channel(fd: i32) -> Result<()> {
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut kind as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    } == 0;
    ensure!(ok, "私有通道不可用：fd 3 不是已连接的套接字");
    ensure!(kind == libc::SOCK_STREAM, "私有通道类型不正确");
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockname(
            fd,
            &mut address as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut length,
        )
    } == 0;
    ensure!(
        ok && address.ss_family as libc::c_int == libc::AF_UNIX,
        "私有通道不是 Unix 域套接字"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options: HashMap<_, _> = args
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| (v[0].as_str(), v[1].as_str()))
        .collect();
    validate_channel(3)?;
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    unsafe {
        libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    socket.set_nonblocking(true)?;
    let (reader, mut writer) = UnixStream::from_std(socket)?.into_split();
    let (tx, mut rx) = mpsc::channel(128);
    let client = Client {
        tx,
        slots: Arc::default(),
        sequence: Arc::new(AtomicU64::new(1)),
        keychain_slots: Arc::default(),
        keychain: Arc::new(tokio::sync::Mutex::new(tokio::io::stdout())),
        log: PathBuf::from(
            options
                .get("--log")
                .copied()
                .unwrap_or(".local/logs/bridge.log"),
        ),
        audit_file: Arc::default(),
    };
    let writer_task = tokio::spawn(async move {
        while let Some(mut value) = rx.recv().await {
            let mut bytes = Zeroizing::new(serde_json::to_vec(&value)?);
            wipe(&mut value);
            bytes.push(b'\n');
            writer.write_all(&bytes).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let key_client = client.clone();
    let key_reader = tokio::spawn(async move {
        let mut reader = BufReader::new(tokio::io::stdin());
        loop {
            let mut line = Zeroizing::new(String::new());
            let n = (&mut reader).take(8193).read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            ensure!(n <= 8192 && line.ends_with('\n'), "钥匙串通道数据无效");
            let value: Value = serde_json::from_str(&line)?;
            if value["privateChannel"] == "pin-store-v1"
                && let Some(id) = value["requestId"].as_u64()
                && let Some(slot) = key_client.keychain_slots.lock().unwrap().remove(&id)
            {
                let _ = slot.send(value);
            }
        }
        key_client.keychain_slots.lock().unwrap().clear();
        Ok::<_, anyhow::Error>(())
    });
    let connections: Connections = Arc::default();
    let (jobs_tx, mut jobs_rx) = mpsc::channel::<Job>(64);
    let scan_pending = Arc::new(AtomicBool::new(false));
    let read_client = client.clone();
    let read_connections = connections.clone();
    let jobs = jobs_tx.clone();
    let reader_task = tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = Zeroizing::new(String::new());
            let n = (&mut reader)
                .take((MAX + 1) as u64)
                .read_line(&mut line)
                .await?;
            ensure!(
                n > 0 && n <= MAX && line.ends_with('\n'),
                "父进程通道已关闭"
            );
            let mut value: Value = serde_json::from_str(&line)?;
            if let Some(id) = value["helperId"]
                .as_u64()
                .or(value["pinId"].as_u64())
                .or(value["controlId"].as_u64())
            {
                if let Some(slot) = read_client.slots.lock().unwrap().remove(&id) {
                    let _ = slot.send(value);
                }
                continue;
            }
            let kind = value["kind"].as_str().unwrap_or("").to_owned();
            let id = value["id"].as_u64().unwrap_or(0);
            let connection_id = value["connection"].as_u64().unwrap_or(0);
            if kind == "close" {
                if let Some(c) = read_connections.lock().unwrap().remove(&connection_id) {
                    c.closed.store(true, Ordering::Relaxed);
                    c.generation.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            let connection = if kind == "rpc" {
                ensure!(connection_id > 0, "连接标识无效");
                let mut map = read_connections.lock().unwrap();
                ensure!(
                    map.len() < 128 || map.contains_key(&connection_id),
                    "连接过多"
                );
                Some((
                    connection_id,
                    map.entry(connection_id)
                        .or_insert_with(|| {
                            Arc::new(Connection {
                                closed: AtomicBool::new(false),
                                subscription: Mutex::new(None),
                                generation: AtomicU64::new(0),
                            })
                        })
                        .clone(),
                ))
            } else {
                None
            };
            let body = value["body"].take();
            let error_request = body.clone();
            if jobs
                .try_send(Job {
                    id,
                    kind: kind.clone(),
                    connection,
                    body,
                })
                .is_err()
            {
                read_client.send(json!({"id":id,"status":if kind=="rpc"{200}else{503},"body":if kind=="rpc"{failure(&error_request,"USBKey 请求队列已满",-11000)}else{json!({})}}))?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    let tick_pending = scan_pending.clone();
    let monitor_connections = connections.clone();
    let monitor_task = tokio::spawn(async move {
        loop {
            // Notifications are only useful while a page holds a subscription.
            // Polling with no subscriber would spawn a probe every second for
            // the whole time the application stays open.
            let watching = monitor_connections
                .lock()
                .unwrap()
                .values()
                .any(|connection| connection.subscription.lock().unwrap().is_some());
            if watching {
                // One scan at a time: the flag stays set until the actor clears it.
                if !tick_pending.swap(true, Ordering::Relaxed)
                    && jobs_tx
                        .try_send(Job {
                            id: 0,
                            kind: "monitor".into(),
                            connection: None,
                            body: Value::Null,
                        })
                        .is_err()
                {
                    tick_pending.store(false, Ordering::Relaxed);
                }
            } else {
                tick_pending.store(false, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut core = rpc::Core::new(client.clone(), connections);
    client.audit(
        "server_start",
        json!({"mode":"rust-native-worker","pid":std::process::id(),"bridgeVersion":VERSION}),
    );
    client.send(json!({"ready":true}))?;
    let actor = async {
        while let Some(job) = jobs_rx.recv().await {
            if job.kind == "monitor" {
                let _ = core.scan().await;
                scan_pending.store(false, Ordering::Relaxed);
                continue;
            }
            if job
                .connection
                .as_ref()
                .is_some_and(|(_, c)| c.closed.load(Ordering::Relaxed))
            {
                continue;
            }
            let mut status = 200;
            // Ask the parent immediately before starting a mutation. A request
            // whose queue waiter expired (or disconnected) is never executed.
            // Admission also tells the parent to await the real final result.
            if matches!(job.kind.as_str(), "selection" | "clear")
                && client.call("controlId", json!({"id":job.id})).await?["allowed"] != true
            {
                continue;
            }
            let body = match job.kind.as_str() {
                "rpc" => core.dispatch(&job.body, job.connection.as_ref()).await,
                "status" => match core.status().await {
                    Ok(v) => v,
                    Err(_) => {
                        status = 503;
                        json!({"service":"netca-ft3000gm","deviceFound":false})
                    }
                },
                "selection" => match core
                    .select(job.body["deviceId"].as_str().unwrap_or(""))
                    .await
                {
                    Ok(v) => v,
                    Err(_) => {
                        status = 400;
                        json!({"error":"所选设备不可用，请刷新设备列表"})
                    }
                },
                "clear" => match core.forget().await {
                    Ok(()) => json!({"cleared":true}),
                    Err(_) => {
                        status = 503;
                        json!({})
                    }
                },
                _ => {
                    status = 400;
                    json!({})
                }
            };
            client.send(json!({"id":job.id,"status":status,"body":body}))?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {result=actor=>result?,result=reader_task=>{result??;},result=writer_task=>{result??;},_ = async {tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap().recv().await;}=>{}}
    monitor_task.abort();
    key_reader.abort();
    Ok(())
}
