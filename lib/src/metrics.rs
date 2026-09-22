use crate::http1_codec::Http1Codec;
use crate::http_codec::HttpCodec;
use crate::tls_demultiplexer::Protocol;
use crate::traffic_limiter::{TrafficDirection, TrafficLimiter};
use crate::{core, http_codec, log_id, log_utils};
use bytes::Bytes;
use prometheus::Encoder;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

const LOG_FMT: &str = "METRICS={}";
const HEALTH_CHECK_PATH: &str = "/health-check";
const METRICS_PATH: &str = "/metrics";
const CLIENTS_PATH: &str = "/clients";
const KICK_PATH: &str = "/kick";

pub(crate) struct Metrics {
    _registry: prometheus::Registry,
    per_client: bool,
    client_sessions: prometheus::IntGaugeVec,
    inbound_traffic: prometheus::IntCounterVec,
    outbound_traffic: prometheus::IntCounterVec,
    client_sessions_per_user: prometheus::IntGaugeVec,
    inbound_traffic_per_user: prometheus::IntCounterVec,
    outbound_traffic_per_user: prometheus::IntCounterVec,
    outbound_tcp_sockets: prometheus::IntGauge,
    outbound_udp_sockets: prometheus::IntGauge,
    clients: Mutex<HashMap<String, ClientInfo>>,
    traffic_limiter: Option<Arc<TrafficLimiter>>,
}

pub(crate) struct KickGate {
    flagged: AtomicBool,
    notify: Notify,
}

impl KickGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            flagged: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub(crate) fn kick(&self) {
        self.flagged.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) async fn wait(&self) {
        loop {
            if self.flagged.load(Ordering::SeqCst) {
                return;
            }
            let notified = self.notify.notified();
            if self.flagged.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

struct ClientInfo {
    username: Option<String>,
    ip: Option<IpAddr>,
    sessions: u64,
    user_agents: BTreeSet<String>,
    kick: Arc<KickGate>,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            username: None,
            ip: None,
            sessions: 0,
            user_agents: BTreeSet::new(),
            kick: KickGate::new(),
        }
    }
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct ClientIpEntry {
    address: String,
    tag: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    user_agents: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct ClientSummary {
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    ips: Vec<ClientIpEntry>,
    sessions: u64,
    inbound: u64,
    outbound: u64,
    total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
    quota_exceeded: bool,
}

pub(crate) struct ClientSessionsCounter {
    metrics: Arc<Metrics>,
    protocol: Protocol,
    conn_id: String,
}

pub(crate) struct OutboundTcpSocketCounter {
    metrics: Arc<Metrics>,
}

pub(crate) struct OutboundUdpSocketCounter {
    metrics: Arc<Metrics>,
}

impl Metrics {
    pub fn new(
        per_client: bool,
        traffic_limiter: Option<Arc<TrafficLimiter>>,
    ) -> io::Result<Arc<Self>> {
        let registry = prometheus::Registry::new();
        Ok(Arc::new(Self {
            per_client,
            client_sessions: prometheus::register_int_gauge_vec_with_registry!(
                "client_sessions",
                "Number of active client sessions",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            inbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "inbound_traffic_bytes",
                "Total number of bytes uploaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "outbound_traffic_bytes",
                "Total number of bytes downloaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            client_sessions_per_user: prometheus::register_int_gauge_vec_with_registry!(
                "client_sessions_per_user",
                "Number of active client sessions per user",
                &["username", "protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            inbound_traffic_per_user: prometheus::register_int_counter_vec_with_registry!(
                "inbound_traffic_bytes_per_user",
                "Total number of bytes uploaded per user",
                &["username"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_traffic_per_user: prometheus::register_int_counter_vec_with_registry!(
                "outbound_traffic_bytes_per_user",
                "Total number of bytes downloaded per user",
                &["username"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_tcp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_tcp_sockets",
                "Number of active outbound TCP connections",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_udp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_udp_sockets",
                "Number of active outbound UDP sockets",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            _registry: registry,
            clients: Mutex::new(HashMap::new()),
            traffic_limiter,
        }))
    }

    pub fn per_client(&self) -> bool {
        self.per_client
    }

    pub fn client_sessions_counter(
        self: Arc<Self>,
        protocol: Protocol,
        conn_id: String,
        username: Option<String>,
    ) -> ClientSessionsCounter {
        ClientSessionsCounter::new(self, protocol, conn_id, username)
    }

    pub fn outbound_tcp_socket_counter(self: Arc<Self>) -> OutboundTcpSocketCounter {
        OutboundTcpSocketCounter::new(self)
    }

    pub fn outbound_udp_socket_counter(self: Arc<Self>) -> OutboundUdpSocketCounter {
        OutboundUdpSocketCounter::new(self)
    }

    pub fn add_inbound_bytes(&self, protocol: Protocol, username: Option<&str>, n: usize) {
        self.inbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
        if self.per_client {
            if let Some(username) = username {
                self.inbound_traffic_per_user
                    .with_label_values(&[username])
                    .inc_by(n as u64);
            }
        }
        if let Some(username) = username.filter(|u| !u.is_empty()) {
            if let Some(limiter) = self.traffic_limiter.as_ref() {
                limiter.record(username, TrafficDirection::Inbound, n);
            }
        }
    }

    pub fn add_outbound_bytes(&self, protocol: Protocol, username: Option<&str>, n: usize) {
        self.outbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
        if self.per_client {
            if let Some(username) = username {
                self.outbound_traffic_per_user
                    .with_label_values(&[username])
                    .inc_by(n as u64);
            }
        }
        if let Some(username) = username.filter(|u| !u.is_empty()) {
            if let Some(limiter) = self.traffic_limiter.as_ref() {
                limiter.record(username, TrafficDirection::Outbound, n);
            }
        }
    }

    fn collect(&self) -> (String, Bytes) {
        let encoder = prometheus::TextEncoder::new();

        let mut metric_families = self._registry.gather();
        metric_families.extend(prometheus::gather());
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        (encoder.format_type().to_string(), Bytes::from(buffer))
    }

    /// Seed the metadata entry for a connection. Only sets the client IP; the
    /// session gauge accounting is owned by the `ClientSessionsCounter` RAII guard.
    pub fn register_connection(&self, conn_id: String, ip: Option<IpAddr>) {
        if let Ok(mut clients) = self.clients.lock() {
            let entry = clients.entry(conn_id).or_default();
            if ip.is_some() {
                entry.ip = ip;
            }
        }
    }

    pub fn note_connection_user_agent(&self, conn_id: &str, user_agent: &str) {
        let Some(ua) = sanitize_user_agent(user_agent) else {
            return;
        };
        let Ok(mut clients) = self.clients.lock() else {
            return;
        };
        if let Some(entry) = clients.get_mut(conn_id) {
            if entry.user_agents.len() >= 8 && !entry.user_agents.contains(&ua) {
                return;
            }
            entry.user_agents.insert(ua);
        }
    }

    /// Remove the metadata entry for a connection that never got a session guard
    /// (e.g. codec creation failed before the tunnel started).
    pub fn unregister_connection(&self, conn_id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(conn_id);
        }
    }

    pub fn connection_kick(&self, conn_id: &str) -> Arc<KickGate> {
        if let Ok(mut clients) = self.clients.lock() {
            return clients.entry(conn_id.to_string()).or_default().kick.clone();
        }
        KickGate::new()
    }

    pub fn kick_user_ip(&self, username: &str, ip: &str) -> u64 {
        let Ok(clients) = self.clients.lock() else {
            return 0;
        };
        let parsed: Option<IpAddr> = ip.parse().ok();
        let mut n = 0u64;
        for info in clients.values() {
            if info.username.as_deref() != Some(username) {
                continue;
            }
            let Some(got) = info.ip else {
                continue;
            };
            let same = parsed.map(|p| p == got).unwrap_or(false) || got.to_string() == ip;
            if !same {
                continue;
            }
            info.kick.kick();
            n = n.saturating_add(1);
        }
        n
    }

    /// Relabel an active session from its current username to a new one.
    /// Used for proxy-basic tunnels whose username is only known after the first
    /// authenticated request. No-op when the label is unchanged. Gauges are only
    /// adjusted for connections that are actually tracked in the clients map, so
    /// the per-user counter always stays balanced.
    pub fn transfer_session_username(
        &self,
        protocol: Protocol,
        conn_id: &str,
        username: Option<String>,
    ) {
        let Ok(mut clients) = self.clients.lock() else {
            return;
        };
        let Some(entry) = clients.get_mut(conn_id) else {
            return;
        };
        let old = entry.username.clone().unwrap_or_default();
        let new = username.clone().unwrap_or_default();
        if old == new {
            return;
        }
        if self.per_client {
            self.client_sessions_per_user
                .with_label_values(&[old.as_str(), protocol.as_str()])
                .dec();
            self.client_sessions_per_user
                .with_label_values(&[new.as_str(), protocol.as_str()])
                .inc();
        }
        entry.username = username;
    }

    /// Aggregate per-user summaries: configured clients (shown even when idle) merged
    /// with runtime connections and lifetime traffic totals from the per-user counters.
    fn clients_summary(&self, configured_usernames: &[String]) -> Vec<ClientSummary> {
        struct AggEntry {
            sessions: u64,
            inbound: u64,
            outbound: u64,
            ips: HashMap<String, BTreeSet<String>>,
        }
        impl Default for AggEntry {
            fn default() -> Self {
                Self {
                    sessions: 0,
                    inbound: 0,
                    outbound: 0,
                    ips: HashMap::new(),
                }
            }
        }

        let mut agg: HashMap<String, AggEntry> = HashMap::new();

        for uname in configured_usernames {
            if !uname.is_empty() {
                agg.entry(uname.clone()).or_default();
            }
        }

        if let Ok(clients_map) = self.clients.lock() {
            for info in clients_map.values() {
                let uname = info.username.clone().unwrap_or_default();
                if uname.is_empty() {
                    continue;
                }
                let entry = agg.entry(uname).or_default();
                entry.sessions = entry.sessions.saturating_add(info.sessions);
                if let Some(ip) = info.ip {
                    entry
                        .ips
                        .entry(ip.to_string())
                        .or_default()
                        .extend(info.user_agents.iter().cloned());
                }
            }
        }

        let mut summaries: Vec<ClientSummary> = agg
            .into_iter()
            .map(|(username, entry)| {
                let mut ips: Vec<ClientIpEntry> = entry
                    .ips
                    .into_iter()
                    .map(|(address, agents)| ClientIpEntry {
                        tag: ip_hashtag(&address),
                        user_agents: agents.into_iter().collect(),
                        address,
                    })
                    .collect();
                ips.sort_by(|a, b| a.address.cmp(&b.address));
                ClientSummary {
                    ip: ips.first().map(|x| x.address.clone()),
                    username,
                    ips,
                    sessions: entry.sessions,
                    inbound: 0,
                    outbound: 0,
                    total: 0,
                    limit: None,
                    quota_exceeded: false,
                }
            })
            .collect();

        if self.per_client {
            for summary in &mut summaries {
                summary.inbound = self
                    .inbound_traffic_per_user
                    .get_metric_with_label_values(&[&summary.username])
                    .map(|c| c.get())
                    .unwrap_or(0);
                summary.outbound = self
                    .outbound_traffic_per_user
                    .get_metric_with_label_values(&[&summary.username])
                    .map(|c| c.get())
                    .unwrap_or(0);
            }
        }

        if let Some(limiter) = self.traffic_limiter.as_ref() {
            for summary in &mut summaries {
                let persisted = limiter.summary(&summary.username);
                summary.inbound = summary.inbound.max(persisted.inbound);
                summary.outbound = summary.outbound.max(persisted.outbound);
                summary.limit = persisted.limit;
                summary.quota_exceeded = persisted.quota_exceeded;
            }
        }

        for summary in &mut summaries {
            summary.total = summary.inbound.saturating_add(summary.outbound);
        }
        summaries.sort_by(|a, b| a.username.cmp(&b.username));
        summaries
    }
}

fn ip_hashtag(address: &str) -> String {
    format!("#ip_{}", address.replace('.', "_").replace(':', "_"))
}

fn sanitize_user_agent(s: &str) -> Option<String> {
    let trimmed: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

impl ClientSessionsCounter {
    fn new(
        metrics: Arc<Metrics>,
        protocol: Protocol,
        conn_id: String,
        username: Option<String>,
    ) -> Self {
        metrics
            .client_sessions
            .with_label_values(&[protocol.as_str()])
            .inc();
        if metrics.per_client {
            let label = username.as_deref().unwrap_or("");
            metrics
                .client_sessions_per_user
                .with_label_values(&[label, protocol.as_str()])
                .inc();
        }

        if let Ok(mut clients) = metrics.clients.lock() {
            let entry = clients.entry(conn_id.clone()).or_default();
            if let Some(u) = username {
                entry.username = Some(u);
            }
            entry.sessions = entry.sessions.saturating_add(1);
        }

        Self {
            metrics: metrics.clone(),
            protocol,
            conn_id,
        }
    }
}

impl Drop for ClientSessionsCounter {
    fn drop(&mut self) {
        self.metrics
            .client_sessions
            .with_label_values(&[self.protocol.as_str()])
            .dec();
        if let Ok(mut clients) = self.metrics.clients.lock() {
            if let Some(entry) = clients.remove(&self.conn_id) {
                if self.metrics.per_client {
                    let label = entry.username.as_deref().unwrap_or("");
                    self.metrics
                        .client_sessions_per_user
                        .with_label_values(&[label, self.protocol.as_str()])
                        .dec();
                }
            }
        }
    }
}

impl OutboundTcpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_tcp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundTcpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_tcp_sockets.dec();
    }
}

impl OutboundUdpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_udp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundUdpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_udp_sockets.dec();
    }
}

pub(crate) async fn listen(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context.shutdown.lock().unwrap();
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::other(format!("{}", e))),
            }
        }
        x = listen_inner(context, log_chain) => x,
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let settings = context.settings.metrics.as_ref();
    if settings.is_none() {
        return Ok(());
    }

    let next_id = AtomicU64::default();
    let listener = TcpListener::bind(settings.unwrap().address).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let log_id = log_chain.extended(log_utils::IdItem::new(
            LOG_FMT,
            next_id.fetch_add(1, Ordering::Relaxed),
        ));
        log_id!(trace, log_id, "New connection from {}", peer);
        let context = context.clone();
        tokio::spawn(async move { handle_request(context, stream, log_id).await });
    }
}

async fn handle_request(
    context: Arc<core::Context>,
    io: TcpStream,
    log_id: log_utils::IdChain<u64>,
) {
    let mut codec = Http1Codec::new(context.settings.clone(), io, log_id.clone());
    let timeout = context.settings.metrics.as_ref().unwrap().request_timeout;
    let stream = match tokio::time::timeout(timeout, codec.listen()).await {
        Ok(Ok(Some(x))) => {
            log_id!(trace, log_id, "Got request: {:?}", x.request().request());
            x
        }
        Ok(Ok(None)) => {
            log_id!(debug, log_id, "Connection closed immediately");
            return;
        }
        Ok(Err(e)) => {
            log_id!(debug, log_id, "Listen failed: {}", e);
            return;
        }
        Err(_elapsed) => {
            log_id!(
                debug,
                log_id,
                "Didn't receive any request during configured period"
            );
            return;
        }
    };

    let dispatch = async {
        match codec.listen().await {
            Ok(Some(x)) => log_id!(
                debug,
                log_id,
                "Got unexpected request while processing previous: {:?}",
                x.request().request(),
            ),
            Ok(None) => (),
            Err(e) => log_id!(debug, log_id, "IO error during processing: {}", e),
        }
    };

    let handle = async {
        let path = stream.request().request().uri.path();
        let result = match path {
            HEALTH_CHECK_PATH => handle_health_check(stream),
            METRICS_PATH => handle_metrics_collect(&context.metrics, stream).await,
            CLIENTS_PATH => handle_clients_collect(context.clone(), &context.metrics, stream).await,
            KICK_PATH => handle_kick(&context.metrics, stream).await,
            x => {
                log_id!(debug, log_id, "Unexpected path: {}", x);
                let respond = stream.split().1;
                if let Err(e) =
                    respond.send_bad_response(http::status::StatusCode::BAD_REQUEST, vec![])
                {
                    log_id!(debug, log_id, "Failed to send response: {}", e);
                }
                return;
            }
        };

        if let Err(e) = result {
            log_id!(debug, log_id, "Failed to handle request: {}", e);
        }
    };

    tokio::select! {
        _ = dispatch => (),
        _ = handle => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

fn handle_health_check(stream: Box<dyn http_codec::Stream>) -> io::Result<()> {
    stream.split().1.send_ok_response(true).map(|_| ())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

async fn send_json(
    stream: Box<dyn http_codec::Stream>,
    status: http::status::StatusCode,
    body: Vec<u8>,
) -> io::Result<()> {
    let mut content = Bytes::from(body);
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();
    while !content.is_empty() {
        content = sink.write(content)?;
        sink.wait_writable().await?;
    }
    sink.eof()
}

async fn handle_kick(metrics: &Metrics, stream: Box<dyn http_codec::Stream>) -> io::Result<()> {
    if !metrics.per_client() {
        let respond = stream.split().1;
        return respond.send_bad_response(http::status::StatusCode::NOT_FOUND, vec![]);
    }
    let uri = &stream.request().request().uri;
    let query = uri.query().unwrap_or("");
    let user = query_param(query, "user").unwrap_or_default();
    let ip = query_param(query, "ip").unwrap_or_default();
    if user.is_empty() || ip.is_empty() || user.len() > 128 || ip.len() > 64 {
        return send_json(
            stream,
            http::status::StatusCode::BAD_REQUEST,
            br#"{"ok":false}"#.to_vec(),
        )
        .await;
    }
    let kicked = metrics.kick_user_ip(&user, &ip);
    let body = format!(r#"{{"ok":true,"kicked":{kicked}}}"#).into_bytes();
    send_json(stream, http::status::StatusCode::OK, body).await
}

async fn handle_clients_collect(
    context: Arc<core::Context>,
    metrics: &Metrics,
    stream: Box<dyn http_codec::Stream>,
) -> io::Result<()> {
    if !metrics.per_client() {
        let respond = stream.split().1;
        return respond.send_bad_response(http::status::StatusCode::NOT_FOUND, vec![]);
    }

    let configured_usernames: Vec<String> = context
        .settings
        .clients
        .iter()
        .map(|c| c.username.clone())
        .collect();
    let content_vec = match serde_json::to_vec(&metrics.clients_summary(&configured_usernames)) {
        Ok(v) => v,
        Err(_) => {
            let respond = stream.split().1;
            return respond
                .send_bad_response(http::status::StatusCode::INTERNAL_SERVER_ERROR, vec![]);
        }
    };
    let mut content = Bytes::from(content_vec);
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(http::status::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();

    while !content.is_empty() {
        content = sink.write(content)?;
        sink.wait_writable().await?;
    }

    sink.eof()
}

async fn handle_metrics_collect(
    metrics: &Metrics,
    stream: Box<dyn http_codec::Stream>,
) -> io::Result<()> {
    let (content_type, mut content) = metrics.collect();
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(http::status::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();

    while !content.is_empty() {
        content = sink.write(content)?;
        sink.wait_writable().await?;
    }

    sink.eof()
}

fn prometheus_to_io_error(e: prometheus::Error) -> io::Error {
    match e {
        prometheus::Error::Io(e) => e,
        e => io::Error::other(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(per_client: bool) -> Arc<Metrics> {
        Metrics::new(per_client, None).unwrap()
    }

    fn output(metrics: &Metrics) -> String {
        let (_, body) = metrics.collect();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[test]
    fn per_user_bytes_recorded_when_enabled() {
        let m = metrics(true);
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 100);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 200);

        let out = output(&m);
        assert!(out.contains("inbound_traffic_bytes{protocol_type=\"HTTP2\"} 100"));
        assert!(out.contains("outbound_traffic_bytes{protocol_type=\"HTTP2\"} 200"));
        assert!(out.contains("inbound_traffic_bytes_per_user{username=\"alice\"} 100"));
        assert!(out.contains("outbound_traffic_bytes_per_user{username=\"alice\"} 200"));
    }

    #[test]
    fn per_user_bytes_not_recorded_when_disabled() {
        let m = metrics(false);
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 100);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 200);

        let out = output(&m);
        assert!(out.contains("inbound_traffic_bytes{protocol_type=\"HTTP2\"} 100"));
        assert!(!out.contains("_per_user"));
    }

    #[test]
    fn session_guard_balances_gauges_on_drop() {
        let m = metrics(true);
        {
            let _guard = m.clone().client_sessions_counter(
                Protocol::Http2,
                "conn1".into(),
                Some("alice".into()),
            );
            let out = output(&m);
            assert!(out.contains("client_sessions{protocol_type=\"HTTP2\"} 1"));
            assert!(out.contains(
                "client_sessions_per_user{protocol_type=\"HTTP2\",username=\"alice\"} 1"
            ));
            assert!(m.clients.lock().unwrap().contains_key("conn1"));
        }

        let out = output(&m);
        assert!(out.contains("client_sessions{protocol_type=\"HTTP2\"} 0"));
        assert!(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"alice\"} 0")
        );
        assert!(!m.clients.lock().unwrap().contains_key("conn1"));
    }

    #[test]
    fn session_guard_disabled_does_not_touch_per_user() {
        let m = metrics(false);
        {
            let _guard = m.clone().client_sessions_counter(
                Protocol::Http2,
                "conn1".into(),
                Some("alice".into()),
            );
            let out = output(&m);
            assert!(out.contains("client_sessions{protocol_type=\"HTTP2\"} 1"));
            assert!(!out.contains("_per_user"));
        }
    }

    #[test]
    fn transfer_session_username_relabels_gauge() {
        let m = metrics(true);
        let _guard = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "conn1".into(), None);

        m.transfer_session_username(Protocol::Http2, "conn1", Some("bob".into()));
        let out = output(&m);
        assert!(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"bob\"} 1")
        );
        assert!(out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"\"} 0"));

        // Transferring to the same username is a no-op.
        m.transfer_session_username(Protocol::Http2, "conn1", Some("bob".into()));
        let out = output(&m);
        assert!(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"bob\"} 1")
        );
    }

    #[test]
    fn unregister_without_guard_is_safe() {
        let m = metrics(true);
        m.register_connection("conn1".into(), Some("127.0.0.1".parse().unwrap()));
        assert!(m.clients.lock().unwrap().contains_key("conn1"));

        m.unregister_connection("conn1");
        assert!(!m.clients.lock().unwrap().contains_key("conn1"));
    }

    #[test]
    fn clients_summary_merges_configured_and_runtime() {
        let m = metrics(true);
        m.register_connection("conn1".into(), Some("127.0.0.1".parse().unwrap()));
        let _guard = m.clone().client_sessions_counter(
            Protocol::Http2,
            "conn1".into(),
            Some("alice".into()),
        );
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 42);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 7);

        let configured = vec!["alice".to_string(), "bob".to_string()];
        let summaries = m.clients_summary(&configured);

        let alice = summaries.iter().find(|s| s.username == "alice").unwrap();
        assert_eq!(alice.sessions, 1);
        assert_eq!(alice.inbound, 42);
        assert_eq!(alice.outbound, 7);
        assert_eq!(alice.ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(alice.ips.len(), 1);
        assert_eq!(alice.ips[0].tag, "#ip_127_0_0_1");
        assert_eq!(alice.total, 49);

        let bob = summaries.iter().find(|s| s.username == "bob").unwrap();
        assert_eq!(bob.sessions, 0);
        assert_eq!(bob.inbound, 0);
        assert_eq!(bob.outbound, 0);
        assert_eq!(bob.ip, None);
    }

    #[test]
    fn clients_summary_shows_zeroes_when_disabled() {
        let m = metrics(false);
        let configured = vec!["alice".to_string()];
        let summaries = m.clients_summary(&configured);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].username, "alice");
        assert_eq!(summaries[0].sessions, 0);
        assert_eq!(summaries[0].inbound, 0);
        assert_eq!(summaries[0].outbound, 0);
    }

    #[test]
    fn clients_summary_keeps_two_user_agents_on_one_nat_ip() {
        let m = metrics(true);
        m.register_connection("conn1".into(), Some("203.0.113.10".parse().unwrap()));
        m.register_connection("conn2".into(), Some("203.0.113.10".parse().unwrap()));
        let _a = m.clone().client_sessions_counter(
            Protocol::Http2,
            "conn1".into(),
            Some("alice".into()),
        );
        let _b = m.clone().client_sessions_counter(
            Protocol::Http2,
            "conn2".into(),
            Some("alice".into()),
        );
        m.note_connection_user_agent("conn1", "Android TrustTunnel");
        m.note_connection_user_agent("conn2", "iOS TrustTunnel");
        m.note_connection_user_agent("conn2", "iOS TrustTunnel");

        let summaries = m.clients_summary(&["alice".into()]);
        let alice = summaries.iter().find(|s| s.username == "alice").unwrap();
        assert_eq!(alice.ips.len(), 1);
        assert_eq!(alice.ips[0].address, "203.0.113.10");
        assert_eq!(
            alice.ips[0].user_agents,
            vec![
                "Android TrustTunnel".to_string(),
                "iOS TrustTunnel".to_string()
            ]
        );
    }

    #[test]
    fn sanitize_user_agent_drops_empty_and_controls() {
        assert_eq!(sanitize_user_agent("  \n"), None);
        assert_eq!(
            sanitize_user_agent("Android\u{0007} 1.4"),
            Some("Android 1.4".into())
        );
    }

    #[test]
    fn query_param_skips_pairs_without_equals() {
        assert_eq!(
            query_param("foo&user=alice&ip=1.2.3.4", "user").as_deref(),
            Some("alice")
        );
        assert_eq!(
            query_param("user=a%3Ab&ip=2001%3Adb8%3A%3A1", "ip").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn kick_user_ip_counts_matching_tls_conns() {
        let m = metrics(true);
        m.register_connection("a1".into(), Some("203.0.113.10".parse().unwrap()));
        m.register_connection("a2".into(), Some("203.0.113.10".parse().unwrap()));
        m.register_connection("a3".into(), Some("198.51.100.1".parse().unwrap()));
        m.register_connection("b1".into(), Some("203.0.113.10".parse().unwrap()));
        let _g1 = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "a1".into(), Some("alice".into()));
        let _g2 = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "a2".into(), Some("alice".into()));
        let _g3 = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "a3".into(), Some("alice".into()));
        let _g4 = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "b1".into(), Some("bob".into()));
        assert_eq!(m.kick_user_ip("alice", "203.0.113.10"), 2);
        assert_eq!(m.kick_user_ip("alice", "198.51.100.1"), 1);
    }
}
