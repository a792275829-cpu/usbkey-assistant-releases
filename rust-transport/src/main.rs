use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{
        Request, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    sync::{Mutex, mpsc, oneshot, watch},
    time::timeout,
};
use zeroize::Zeroizing;

mod device_process;
mod pin_session;

const ORIGIN: &str = "https://pm.gd.csg.cn";
const PROTOCOL: &str = "crypto-jsonrpc-protocol";
const MAX_MESSAGE: usize = 1024 * 1024;
// RPC responses repeat Base64 values under legacy aliases (up to six copies).
const MAX_IPC: usize = 16 * MAX_MESSAGE;
// A status read must never be held hostage by a PIN prompt or a slow helper.
// The panel prefers the last known answer over a false "device disconnected".
const STATUS_WAIT: Duration = Duration::from_secs(3);
const CONTROL_WAIT: Duration = Duration::from_secs(10);
struct PendingRequest {
    reply: oneshot::Sender<Value>,
    control: Option<(Instant, Arc<AtomicBool>)>,
}
type Pending = HashMap<u64, PendingRequest>;
type Connections = HashMap<u64, (mpsc::Sender<Message>, watch::Sender<bool>)>;
type Snapshot = Arc<StdMutex<Option<Value>>>;

// Remove abandoned requests even if a WebSocket disconnect aborts the future.
struct PendingGuard(u64, Arc<StdMutex<Pending>>);
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.1.lock().unwrap().remove(&self.0);
    }
}

#[derive(Clone)]
struct Worker {
    tx: mpsc::Sender<Value>,
    pending: Arc<StdMutex<Pending>>,
    connections: Arc<Mutex<Connections>>,
    sequence: Arc<AtomicU64>,
    shutdown: watch::Sender<bool>,
    snapshot: Snapshot,
    status_refresh: Arc<Mutex<()>>,
    status_updates: watch::Sender<Option<Value>>,
}

impl Worker {
    async fn request(&self, kind: &str, connection: u64, body: Value) -> Result<Value> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = oneshot::channel();
        let control = matches!(kind, "selection" | "clear").then(|| {
            (
                Instant::now() + CONTROL_WAIT,
                Arc::new(AtomicBool::new(false)),
            )
        });
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 64 {
                bail!("USBKey 请求队列已满");
            }
            pending.insert(
                id,
                PendingRequest {
                    reply: tx,
                    control: control.clone(),
                },
            );
        }
        let _guard = PendingGuard(id, self.pending.clone());
        async {
            self.tx.try_send(
                json!({"id": id, "kind": kind, "connection": connection, "body": body}),
            )?;
            if let Some((until, admitted)) = control {
                match timeout(until.saturating_duration_since(Instant::now()), &mut rx).await {
                    Ok(result) => return Ok(result?),
                    // Once authorized, wait for the operation's actual result.
                    // The IPC reader cannot grant a request after its deadline.
                    Err(_) => {
                        // Serialize expiry with admission: neither side can
                        // observe an unadmitted job then grant it afterwards.
                        let mut pending = self.pending.lock().unwrap();
                        if !admitted.load(Ordering::SeqCst) {
                            pending.remove(&id);
                            bail!("USBKey 控制请求排队超时");
                        }
                    }
                }
            }
            // Business operations and admitted controls use their existing
            // hardware/Keychain deadlines, not a detached HTTP waiter timeout.
            Ok(rx.await?)
        }
        .await
    }
}

fn failure(request: &Value, message: &str) -> Value {
    let mut value = json!({"responseVersion": 1,
        "requestVersion": request.get("requestVersion").filter(|v| !v.is_null()).cloned().unwrap_or(json!(1)),
        "responseResult": {"status": -11000, "msg": message}, "responseEntity": {}});
    for key in ["lwsObjectId", "requestOrigin", "requestId"] {
        if let Some(v) = request.get(key) {
            value[key] = v.clone();
        }
    }
    value
}

fn private_request(headers: &HeaderMap) -> bool {
    !headers.contains_key(header::ORIGIN)
        && headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("application/json")
            })
}

fn response(status: StatusCode, body: impl IntoResponse) -> Response {
    let mut result = (status, body).into_response();
    result.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    result
}

async fn route(
    State(worker): State<Worker>,
    ws: std::result::Result<
        WebSocketUpgrade,
        axum::extract::ws::rejection::WebSocketUpgradeRejection,
    >,
    request: Request,
) -> Response {
    let headers = request.headers();
    if headers.get(header::UPGRADE).is_some() {
        let allowed = headers.get_all(header::ORIGIN).iter().count() == 1
            && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(ORIGIN)
            && headers
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|s| s.trim() == PROTOCOL));
        if !allowed {
            return StatusCode::FORBIDDEN.into_response();
        }
        if !headers.get(header::SEC_WEBSOCKET_KEY).is_some_and(|key| {
            base64::engine::general_purpose::STANDARD
                .decode(key.as_bytes())
                .is_ok_and(|bytes| bytes.len() == 16)
        }) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match ws {
            Ok(ws) => ws
                .protocols([PROTOCOL])
                .max_message_size(MAX_MESSAGE)
                .max_frame_size(MAX_MESSAGE)
                .write_buffer_size(0)
                .max_write_buffer_size(MAX_IPC)
                .on_upgrade(move |socket| websocket(socket, worker)),
            Err(_) => StatusCode::BAD_REQUEST.into_response(),
        };
    }
    let kind = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/health") => return response(StatusCode::OK, "netca-ft3000gm"),
        ("GET", "/status") => {
            if headers.contains_key(header::ORIGIN) {
                return StatusCode::FORBIDDEN.into_response();
            }
            "status"
        }
        ("POST", "/selection" | "/pin-cache/clear") => {
            if !private_request(headers) {
                return StatusCode::FORBIDDEN.into_response();
            }
            if request.uri().path() == "/selection" {
                "selection"
            } else {
                "clear"
            }
        }
        _ => return response(StatusCode::OK, "NETCA macOS FT3000GM bridge\n"),
    };
    let body = if kind == "selection" || kind == "clear" {
        match timeout(Duration::from_secs(5), to_bytes(request.into_body(), 1024)).await {
            Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
            Ok(Err(_)) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            Ok(Ok(bytes)) if kind == "selection" => match serde_json::from_slice(&bytes) {
                Ok(body) => body,
                Err(_) => {
                    return response(
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "所选设备不可用，请刷新设备列表"})),
                    );
                }
            },
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    if kind == "status" {
        return status_response(&worker).await;
    }
    match worker.request(kind, 0, body).await {
        Ok(result) => response(status_code(&result), Json(result["body"].clone())),
        _ => response(StatusCode::SERVICE_UNAVAILABLE, Json(json!({}))),
    }
}

fn status_code(result: &Value) -> StatusCode {
    result["status"]
        .as_u64()
        .and_then(|code| u16::try_from(code).ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
}

async fn status_response(worker: &Worker) -> Response {
    let mut updates = worker.status_updates.subscribe();
    if let Ok(guard) = worker.status_refresh.clone().try_lock_owned() {
        let worker = worker.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let result = worker.request("status", 0, Value::Null).await.ok();
            if let Some(result) = &result
                && status_code(result) == StatusCode::OK
            {
                *worker.snapshot.lock().unwrap() = Some(result["body"].clone());
            }
            // Complete independently of HTTP lifetimes, and wake all readers
            // sharing this scan rather than enqueueing another hardware read.
            worker.status_updates.send_replace(result);
        });
    }
    let result = match timeout(STATUS_WAIT, updates.changed()).await {
        Ok(Ok(())) => updates.borrow().clone(),
        _ => None,
    };
    if let Some(result) = result {
        let code = status_code(&result);
        let body = result["body"].clone();
        return response(code, Json(body));
    }
    // The worker is busy, typically holding a PIN prompt. Reporting "no device"
    // here would look like a hardware failure while the user is typing a PIN.
    let cached = worker.snapshot.lock().unwrap().clone();
    match cached {
        Some(mut body) => {
            if let Some(map) = body.as_object_mut() {
                map.insert("stale".into(), json!(true));
            }
            response(StatusCode::OK, Json(body))
        }
        None => response(
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"service": "netca-ft3000gm", "deviceFound": false})),
        ),
    }
}

async fn websocket(socket: WebSocket, worker: Worker) {
    let id = worker.sequence.fetch_add(1, Ordering::Relaxed);
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let (jobs_tx, mut jobs_rx) = mpsc::channel::<String>(64);
    let (close_tx, mut close_rx) = watch::channel(false);
    {
        let mut connections = worker.connections.lock().await;
        if connections.len() >= 128 {
            return;
        }
        connections.insert(id, (out_tx.clone(), close_tx));
    }
    let (mut sink, mut stream) = socket.split();
    let job_worker = worker.clone();
    let job_output = out_tx.clone();
    let mut jobs = tokio::spawn(async move {
        while let Some(text) = jobs_rx.recv().await {
            let result = match serde_json::from_str::<Value>(&text) {
                Ok(request) => match job_worker.request("rpc", id, request.clone()).await {
                    Ok(reply) => reply["body"].clone(),
                    Err(_) => failure(&request, "USBKey 服务繁忙或不可用，请重新操作"),
                },
                Err(_) => failure(&Value::Null, "请求不是有效的 JSON"),
            };
            if job_output
                .try_send(Message::Text(result.to_string().into()))
                .is_err()
            {
                break;
            }
        }
    });
    let mut writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if matches!(message, Message::Close(_)) {
                let _ = timeout(Duration::from_secs(2), sink.close()).await;
                break;
            }
            if !matches!(
                timeout(Duration::from_secs(5), sink.send(message)).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    });
    loop {
        tokio::select! {
            _ = close_rx.changed() => break,
            _ = &mut writer => break,
            _ = &mut jobs => break,
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    if jobs_tx.try_send(text.to_string()).is_err() { break; }
                }
                // Tungstenite queues and flushes the RFC-required Pong itself.
                Some(Ok(Message::Ping(_))) => {},
                Some(Ok(Message::Pong(_))) => {},
                Some(Ok(Message::Close(_))) => {
                    let _ = out_tx.try_send(Message::Close(None));
                    let _ = timeout(Duration::from_secs(2), &mut writer).await;
                    break;
                }
                _ => break,
            }
        }
    }
    writer.abort();
    jobs.abort();
    worker.connections.lock().await.remove(&id);
    // Never silently lose a disconnect: dropping the worker closes all sessions.
    if worker
        .tx
        .try_send(json!({"kind": "close", "connection": id}))
        .is_err()
    {
        let _ = worker.shutdown.send(true);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.len().is_multiple_of(2) {
        bail!("arguments must be --name value pairs");
    }
    let options: HashMap<&str, &str> = args
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| (v[0].as_str(), v[1].as_str()))
        .collect();
    let required = |name: &str| -> Result<String> {
        options
            .get(name)
            .map(|v| v.to_string())
            .with_context(|| format!("missing {name}"))
    };
    let port: u16 = options.get("--port").unwrap_or(&"10443").parse()?;
    let parent_pid: i32 = options.get("--parent-pid").unwrap_or(&"0").parse()?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        required("--cert")?,
        required("--key")?,
    )
    .await?;
    // Bind before starting the worker/supervisor so startup errors cannot leave
    // a hardware operation running outside the coordinated shutdown path.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let server = axum_server::from_tcp_rustls(listener, tls)?;
    if options.contains_key("--node") || options.contains_key("--worker") {
        bail!("legacy JavaScript workers are no longer supported");
    }
    let worker_path = options
        .get("--native-worker")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?.with_file_name("usbkey-worker"));
    let root = worker_path
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or_else(|| std::path::Path::new("."));
    let helpers = device_process::Helpers {
        probe: options
            .get("--probe")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("build/ft3000gm-hid-probe")),
        signer: options
            .get("--signer")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("build/ft3000gm-signer")),
    };
    let (parent, child_socket) = std::os::unix::net::UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let child_fd = child_socket.as_raw_fd();
    let mut command = Command::new(&worker_path);
    command
        .args(&args)
        .env("USBKEY_RUST_WORKER", "1")
        .kill_on_drop(true);
    // fd 3 is private IPC. Preserve stdin/stdout for the Swift Keychain channel.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("cannot start business worker")?;
    drop(child_socket);
    let (reader, mut writer) = UnixStream::from_std(parent)?.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    timeout(
        Duration::from_secs(10),
        (&mut reader)
            .take((MAX_IPC + 1) as u64)
            .read_line(&mut line),
    )
    .await??;
    if line.len() > MAX_IPC || serde_json::from_str::<Value>(&line)?["ready"] != true {
        bail!("worker not ready");
    }
    let (tx, mut rx) = mpsc::channel::<Value>(128);
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let (helper_tx, helper_rx) = mpsc::channel(64);
    let (helper_stop, helper_stopped) = watch::channel(false);
    let pin_state = Arc::new(StdMutex::new(pin_session::Session::default()));
    let sweep_state = pin_state.clone();
    let mut sweep_stop = helper_stopped.clone();
    let pin_sweeper = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sweep_stop.changed() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) =>
                    sweep_state.lock().unwrap().expire(std::time::Instant::now()),
            }
        }
        sweep_state.lock().unwrap().close();
    });
    let helper_task = tokio::spawn(device_process::supervise(
        helper_rx,
        tx.clone(),
        helpers,
        helper_stopped,
        shutdown.clone(),
        pin_state.clone(),
    ));
    let worker = Worker {
        tx,
        pending: Arc::default(),
        connections: Arc::default(),
        sequence: Arc::new(AtomicU64::new(1)),
        shutdown,
        snapshot: Arc::default(),
        status_refresh: Arc::default(),
        status_updates: watch::channel(None).0,
    };
    let write_task = tokio::spawn(async move {
        while let Some(mut value) = rx.recv().await {
            let mut data = Zeroizing::new(serde_json::to_vec(&value)?);
            if let Some(result) = value.get_mut("result") {
                for key in ["pin", "stdout"] {
                    if let Some(Value::String(pin)) = result.get_mut(key) {
                        zeroize::Zeroize::zeroize(pin);
                    }
                }
            }
            data.push(b'\n');
            timeout(Duration::from_secs(5), writer.write_all(&data)).await??;
        }
        Ok::<_, anyhow::Error>(())
    });
    let read_worker = worker.clone();
    let read_task = tokio::spawn(async move {
        loop {
            let mut line = Zeroizing::new(String::new());
            let n = (&mut reader)
                .take((MAX_IPC + 1) as u64)
                .read_line(&mut line)
                .await?;
            if n == 0 || n > MAX_IPC || !line.ends_with('\n') {
                bail!("worker IPC closed or oversized");
            }
            let mut value: Value = serde_json::from_str(&line)?;
            if let Some(id) = value["controlId"].as_u64() {
                let allowed = {
                    let pending = read_worker.pending.lock().unwrap();
                    value["request"]["id"]
                        .as_u64()
                        .and_then(|id| pending.get(&id))
                        .and_then(|entry| entry.control.as_ref())
                        .is_some_and(|(until, admitted)| {
                            if Instant::now() >= *until {
                                return false;
                            }
                            admitted.store(true, Ordering::SeqCst);
                            true
                        })
                };
                read_worker
                    .tx
                    .try_send(json!({"controlId":id,"result":{"allowed":allowed}}))?;
            } else if let Some(id) = value["pinId"].as_u64() {
                let result = serde_json::from_value(value["request"].take())
                    .map_err(|_| "invalid_command")
                    .and_then(|request| {
                        pin_state
                            .lock()
                            .unwrap()
                            .handle(request, std::time::Instant::now())
                    });
                let reply = match result {
                    Ok(result) => {
                        let mut reply = json!({"pinId": id});
                        reply["result"] = result;
                        reply
                    }
                    Err(error) => json!({"pinId": id, "error": error}),
                };
                read_worker.tx.try_send(reply)?;
            } else if let Some(id) = value["helperId"].as_u64() {
                let request = serde_json::from_value(value["request"].take());
                let error = match request {
                    Ok(request) => {
                        if helper_tx
                            .try_send(device_process::Job { id, request })
                            .is_err()
                        {
                            Some("queue_full")
                        } else {
                            None
                        }
                    }
                    Err(_) => Some("invalid_request"),
                };
                if let Some(error) = error {
                    read_worker
                        .tx
                        .try_send(json!({"helperId": id, "error": error}))?;
                }
            } else if let Some(id) = value["id"].as_u64() {
                if let Some(tx) = read_worker.pending.lock().unwrap().remove(&id) {
                    let _ = tx.reply.send(value);
                }
            } else if let Some(id) = value["connection"].as_u64() {
                let connections = read_worker.connections.lock().await;
                if let Some((tx, close)) = connections.get(&id)
                    && tx
                        .try_send(Message::Text(value["response"].to_string().into()))
                        .is_err()
                {
                    let _ = close.send(true);
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    let app = Router::new().fallback(any(route)).with_state(worker);
    eprintln!(
        "USBKey Rust transport listening on 127.0.0.1:{}",
        address.port()
    );
    let server = server.serve(app.into_make_service());
    let parent_monitor = async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if parent_pid > 1
                && unsafe { libc::kill(parent_pid, 0) } != 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                break;
            }
        }
    };
    let result = tokio::select! {
        result = server => result.map_err(anyhow::Error::from),
        _ = child.wait() => Err(anyhow::anyhow!("business worker exited")),
        _ = read_task => Err(anyhow::anyhow!("business worker IPC reader stopped")),
        _ = write_task => Err(anyhow::anyhow!("business worker IPC writer stopped")),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = async { tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap().recv().await; } => Ok(()),
        _ = parent_monitor => Ok(()),
        _ = shutdown_rx.changed() => Err(anyhow::anyhow!("cannot deliver private IPC message")),
    };
    let _ = helper_stop.send(true);
    child.kill().await.ok();
    helper_task.await??;
    pin_sweeper.await?;
    result
}
