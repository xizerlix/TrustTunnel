use crate::authentication::Status;
use crate::connection_limiter::ConnectionGuard;
use crate::dest_stats::{self, DestinationStats};
use crate::downstream::{
    Downstream, PendingDatagramMultiplexerRequest, PendingDemultiplexedRequest,
    PendingTcpConnectRequest,
};
use crate::forwarder::Forwarder;
use crate::net_utils::TcpDestination;
use crate::pipe::DuplexPipe;
use crate::rules::RulesEngine;
use crate::{
    authentication, core, datagram_pipe, downstream, forwarder, log_id, log_utils, net_utils, pipe,
    udp_pipe,
};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

struct ActiveForwardGuard(Arc<AtomicU64>);

impl Drop for ActiveForwardGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Extract the username from base64-encoded `username:password` credentials.
fn decode_username(creds: &str) -> Option<String> {
    BASE64_ENGINE
        .decode(creds)
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|s| s.split(':').next().map(|x| x.to_string()))
}

fn username_from_auth(
    source: Option<&authentication::Source<'_>>,
    authenticator: Option<&dyn authentication::Authenticator>,
) -> Option<String> {
    let source = source?;
    if let Some(name) = authenticator.and_then(|a| a.username(source)) {
        return Some(name);
    }
    let creds = match source {
        authentication::Source::ProxyBasic(s) => s.as_ref(),
        authentication::Source::Sni(s) => s.as_ref(),
    };
    decode_username(creds)
}

#[derive(Clone)]
pub(crate) enum AuthenticationPolicy<'this> {
    /// Perform the regular authentication procedure through the configured authenticator
    Default,
    /// The whole connection is authenticated.
    /// Contains the authenticated info.
    Authenticated(authentication::Source<'this>),
}

pub(crate) struct Tunnel {
    context: Arc<core::Context>,
    downstream: Box<dyn Downstream>,
    forwarder: Arc<dyn Forwarder>,
    authentication_policy: AuthenticationPolicy<'static>,
    /// Holds the connection slot acquired for this tunnel.
    /// Set at construction time for SNI-authenticated connections,
    /// or lazily on the first authenticated request for proxy-basic connections.
    connection_guard: Option<ConnectionGuard>,
    active_forwards: Arc<AtomicU64>,
    id: log_utils::IdChain<u64>,
}

#[derive(Debug)]
pub(crate) enum ConnectionError {
    Io(io::Error),
    Authentication(String),
    Timeout,
    HostUnreachable,
    DnsNonroutable,
    DnsLoopback,
    Other(String),
}

impl Display for ConnectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(x) => write!(f, "IO error: {}", x),
            Self::Authentication(x) => write!(f, "Authentication error: {}", x),
            Self::Timeout => write!(f, "Connection timed out"),
            Self::HostUnreachable => write!(f, "Remote host is unreachable"),
            Self::DnsNonroutable => write!(f, "DNS: resolved address in non-routable network"),
            Self::DnsLoopback => write!(f, "DNS: resolved address in loopback"),
            Self::Other(x) => write!(f, "{}", x),
        }
    }
}

impl Tunnel {
    pub fn new(
        context: Arc<core::Context>,
        downstream: Box<dyn Downstream>,
        forwarder: Box<dyn Forwarder>,
        authentication_policy: AuthenticationPolicy<'static>,
        connection_guard: Option<ConnectionGuard>,
        id: log_utils::IdChain<u64>,
    ) -> Self {
        Self {
            context,
            downstream,
            forwarder: Arc::from(forwarder),
            authentication_policy,
            connection_guard,
            active_forwards: Arc::new(AtomicU64::new(0)),
            id,
        }
    }

    pub async fn listen(&mut self) -> io::Result<()> {
        let (mut shutdown_notification, _shutdown_completion) = {
            let shutdown = self.context.shutdown.lock().unwrap();
            (shutdown.notification_handler(), shutdown.completion_guard())
        };
        let kick = self.context.metrics.connection_kick(&self.id.to_string());
        tokio::select! {
            x = shutdown_notification.wait() => {
                match x {
                    Ok(_) => self.downstream.graceful_shutdown().await,
                    Err(e) => Err(io::Error::other(format!("{}", e))),
                }
            }
            _ = kick.wait() => {
                log_id!(debug, self.id, "Tunnel kicked");
                self.downstream.graceful_shutdown().await
            }
            x = self.listen_inner() => x,
        }
    }

    fn resolve_username(
        &self,
        request: &dyn downstream::PendingMultiplexedRequest,
    ) -> Option<String> {
        match &self.authentication_policy {
            AuthenticationPolicy::Authenticated(source) => {
                self.context.authenticator.as_ref()?.username(source)
            }
            AuthenticationPolicy::Default => match request.auth_info() {
                Ok(Some(source)) => match &source {
                    authentication::Source::ProxyBasic(s) => decode_username(s.as_ref()),
                    authentication::Source::Sni(s) => decode_username(s.as_ref()),
                },
                _ => None,
            },
        }
    }

    async fn listen_inner(&mut self) -> io::Result<()> {
        loop {
            log_id!(trace, self.id, "Tunnel waiting for request");
            let request = match tokio::time::timeout(
                self.context.settings.client_listener_timeout,
                self.downstream.listen(),
            )
            .await
            {
                Ok(Ok(None)) => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Ok(Some(r))) => {
                    log_id!(trace, self.id, "Tunnel received request");
                    r
                }
                Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    log_id!(trace, self.id, "Tunnel listen error: {}", e);
                    return Err(e);
                }
                Err(_) => {
                    if self.active_forwards.load(Ordering::Relaxed) > 0 {
                        log_id!(
                            trace,
                            self.id,
                            "Tunnel listen timeout ignored: {} active forwards",
                            self.active_forwards.load(Ordering::Relaxed)
                        );
                        continue;
                    }
                    log_id!(trace, self.id, "Tunnel listen timeout");
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
            };

            let context = self.context.clone();
            let forwarder = self.forwarder.clone();
            let tls_domain = self.downstream.tls_domain().to_string();
            let authentication_policy = self.authentication_policy.clone();
            let log_id = self.id.clone();
            let protocol = self.downstream.protocol();
            let username = if context.metrics.per_client() {
                self.resolve_username(request.as_ref())
            } else {
                None
            };
            let update_metrics = {
                let metrics = context.metrics.clone();
                move |direction, n| match direction {
                    pipe::SimplexDirection::Incoming => {
                        metrics.add_inbound_bytes(protocol, username.as_deref(), n)
                    }
                    pipe::SimplexDirection::Outgoing => {
                        metrics.add_outbound_bytes(protocol, username.as_deref(), n)
                    }
                }
            };

            // For proxy-basic connections, lazily acquire the connection slot on the first
            // authenticated request. This means the limit applies to active tunnels that have
            // sent at least one request, not to idle connections. This is done before spawning
            // so the guard lifetime matches the tunnel, not an individual request task.
            if self.connection_guard.is_none() {
                if let Some(limiter) = self.context.connection_limiter.as_ref() {
                    let auth_info = request
                        .auth_info()
                        .map(|x| x.map(authentication::Source::into_owned));
                    let protocol = self.downstream.protocol();
                    if let Ok(Some(source)) = auth_info {
                        let authenticated = self
                            .context
                            .authenticator
                            .as_ref()
                            .map(|a| a.authenticate(&source, &self.id) == Status::Pass)
                            .unwrap_or(false);
                        if authenticated {
                            if let Some(username) = decode_username(match &source {
                                authentication::Source::ProxyBasic(s) => s.as_ref(),
                                authentication::Source::Sni(s) => s.as_ref(),
                            }) {
                                if context.traffic_limiter.as_ref().is_some_and(|limiter| {
                                    !limiter.is_allowed(&username)
                                }) {
                                    log_id!(
                                        debug,
                                        self.id,
                                        "Traffic quota exceeded, closing tunnel"
                                    );
                                    request.fail_request(ConnectionError::Authentication(
                                        "Traffic quota exceeded".to_string(),
                                    ));
                                    return Err(io::Error::new(
                                        ErrorKind::PermissionDenied,
                                        "Traffic quota exceeded",
                                    ));
                                }
                            }
                            let creds = match &source {
                                authentication::Source::ProxyBasic(s) => s.as_ref(),
                                authentication::Source::Sni(s) => s.as_ref(),
                            };
                            match limiter.try_acquire(creds, protocol) {
                                Some(guard) => {
                                    self.connection_guard = Some(guard);
                                }
                                None => {
                                    log_id!(
                                        debug,
                                        self.id,
                                        "Connection limit exceeded, closing tunnel"
                                    );
                                    request.fail_request(ConnectionError::Authentication(
                                        "Connection limit exceeded".to_string(),
                                    ));
                                    return Err(io::Error::new(
                                        ErrorKind::PermissionDenied,
                                        "Connection limit exceeded",
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            self.active_forwards.fetch_add(1, Ordering::Relaxed);
            let _active_forward = ActiveForwardGuard(self.active_forwards.clone());
            tokio::spawn(async move {
                let _active_forward = _active_forward;
                fn report_fatal_if_too_many_open_files(
                    context: &Arc<core::Context>,
                    e: &ConnectionError,
                ) {
                    if let ConnectionError::Io(io) = e {
                        if core::Core::is_too_many_open_files_error(io) {
                            context.report_fatal_io_error(io);
                        }
                    }
                }

                let request_id = request.id();
                log_id!(trace, request_id, "Processing tunnel request");
                let auth_info_result = request
                    .auth_info()
                    .map(|x| x.map(authentication::Source::into_owned));
                let forwarder_auth = match (
                    auth_info_result.as_ref().cloned(),
                    authentication_policy,
                    context.authenticator.clone(),
                ) {
                    (Ok(Some(source)), _, Some(authenticator)) => {
                        match authenticator.authenticate(&source, &log_id) {
                            Status::Pass => Some(source),
                            Status::Reject => {
                                let err = ConnectionError::Authentication(
                                    "Authentication failed".to_string(),
                                );
                                log_id!(debug, request_id, "{}", err);
                                request.fail_request(err);
                                return;
                            }
                        }
                    }
                    (Ok(None), AuthenticationPolicy::Authenticated(x), Some(_)) => Some(x),
                    (Ok(x), policy, None) => x.or(match policy {
                        AuthenticationPolicy::Default => None,
                        AuthenticationPolicy::Authenticated(y) => Some(y),
                    }),
                    (Ok(None), AuthenticationPolicy::Default, Some(_)) => {
                        let err = ConnectionError::Authentication(
                            "Got request without authentication info on non-authenticated connection".to_string()
                        );
                        log_id!(debug, request_id, "{}", err);
                        request.fail_request(err);
                        return;
                    }
                    (Err(e), ..) => {
                        log_id!(debug, request_id, "Failed to get auth info: {}", e);
                        request.fail_request(ConnectionError::Io(io::Error::new(
                            e.kind(),
                            e.to_string(),
                        )));
                        return;
                    }
                };

                log_id!(
                    trace,
                    request_id,
                    "Authentication complete, promoting request"
                );

                // If this request carried credentials, relabel the session
                // with the authenticated username (no-op if it's already labelled).
                if let Ok(Some(source)) = auth_info_result {
                    let username_opt = match &source {
                        authentication::Source::ProxyBasic(s) => decode_username(s.as_ref()),
                        authentication::Source::Sni(s) => decode_username(s.as_ref()),
                    };
                    if let Some(u) = username_opt {
                        if context
                            .traffic_limiter
                            .as_ref()
                            .is_some_and(|limiter| !limiter.is_allowed(&u))
                        {
                            let err = ConnectionError::Authentication(
                                "Traffic quota exceeded".to_string(),
                            );
                            log_id!(debug, request_id, "{}", err);
                            request.fail_request(err);
                            return;
                        }
                        context.metrics.transfer_session_username(
                            protocol,
                            &log_id.to_string(),
                            Some(u),
                        );
                    }
                }
                if let Some(ua) = request.user_agent() {
                    context
                        .metrics
                        .note_connection_user_agent(&log_id.to_string(), &ua);
                }
                match request.promote_to_next_state() {
                    Ok(None) => {
                        log_id!(trace, request_id, "Health check request completed");
                    }
                    Ok(Some(PendingDemultiplexedRequest::TcpConnect(request))) => {
                        log_id!(trace, request_id, "Handling TCP connect request");
                        if let Err((request, message, e)) = Tunnel::on_tcp_connect_request(
                            context.clone(),
                            forwarder,
                            request,
                            forwarder_auth,
                            tls_domain,
                            update_metrics,
                        )
                        .await
                        {
                            report_fatal_if_too_many_open_files(&context, &e);
                            log_id!(debug, request_id, "{}: {}", message, e);
                            if let Some(request) = request {
                                request.fail_request(e);
                            }
                        }
                    }
                    Ok(Some(PendingDemultiplexedRequest::DatagramMultiplexer(request))) => {
                        log_id!(trace, request_id, "Handling datagram multiplexer request");
                        if let Err((request, message, e)) = Tunnel::on_datagram_mux_request(
                            context.clone(),
                            forwarder,
                            request,
                            forwarder_auth,
                            tls_domain,
                            update_metrics,
                        )
                        .await
                        {
                            report_fatal_if_too_many_open_files(&context, &e);
                            log_id!(debug, request_id, "{}: {}", message, e);
                            if let Some(request) = request {
                                request.fail_request(e);
                            }
                        }
                    }
                    Err(e) => {
                        log_id!(debug, request_id, "Failed to complete request: {}", e);
                    }
                }
            });
        }
    }

    async fn on_tcp_connect_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone>(
        context: Arc<core::Context>,
        forwarder: Arc<dyn Forwarder>,
        request: Box<dyn PendingTcpConnectRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<
        (),
        (
            Option<Box<dyn PendingTcpConnectRequest>>,
            &'static str,
            ConnectionError,
        ),
    > {
        let request_id = request.id();
        log_id!(trace, request_id, "TCP connect: extracting destination");
        let destination = match request.destination() {
            Ok(d) => {
                log_id!(trace, request_id, "TCP connect: destination={:?}", d);
                d
            }
            Err(e) => {
                return Err((
                    Some(request),
                    "Failed to get destination",
                    ConnectionError::Io(e),
                ))
            }
        };

        let username_opt = username_from_auth(
            forwarder_auth.as_ref(),
            context.authenticator.as_ref().map(|a| a.as_ref()),
        );

        let meta = forwarder::TcpConnectionMeta {
            client_address: match request.client_address() {
                Ok(x) => x,
                Err(e) => {
                    return Err((
                        Some(request),
                        "Failed to get client address",
                        ConnectionError::Io(e),
                    ))
                }
            },
            destination,
            tls_domain,
            auth: forwarder_auth,
            user_agent: request.user_agent(),
        };

        if let Some(engine) = context.settings.rules_engine.as_ref() {
            if let TcpDestination::HostName((host, _)) = &meta.destination {
                if engine.denies_destination(Some(&meta.client_address), host) {
                    log_id!(
                        debug,
                        request_id,
                        "TCP connect denied by domain rule: {}",
                        host
                    );
                    return Err((
                        Some(request),
                        "Destination denied by filtering rules",
                        ConnectionError::Other("destination denied".into()),
                    ));
                }
            }
        }

        log_id!(trace, request_id, "TCP connect: connecting to peer");
        let connector = forwarder.tcp_connector();
        let (fwd_rx, fwd_tx) = match tokio::time::timeout(
            context.settings.connection_establishment_timeout,
            connector.connect(request_id.clone(), meta.clone()),
        )
        .await
        .unwrap_or(Err(ConnectionError::Timeout))
        {
            Ok(x) => {
                log_id!(
                    trace,
                    request_id,
                    "TCP connect: peer connection established"
                );
                if let Some(username) = username_opt.as_ref() {
                    context
                        .dest_stats
                        .record_destination(username, &meta.destination);
                }
                x
            }
            Err(e) => return Err((Some(request), "Connection to peer failed", e)),
        };

        log_id!(debug, request_id, "Successfully connected to {:?}", meta);
        log_id!(
            trace,
            request_id,
            "TCP connect: promoting downstream request"
        );
        let (dstr_rx, dstr_tx) = match request.promote_to_next_state() {
            Ok(x) => {
                log_id!(
                    trace,
                    request_id,
                    "TCP connect: downstream ready, starting pipe"
                );
                x
            }
            Err(e) => return Err((None, "Failed to complete request", ConnectionError::Io(e))),
        };

        let dstr_rx = if matches!(meta.destination, TcpDestination::HostName(_)) {
            dstr_rx
        } else {
            Box::new(SniPeekSource::new(
                dstr_rx,
                context.dest_stats.clone(),
                context.settings.rules_engine.clone(),
                meta.client_address,
                username_opt.clone().unwrap_or_default(),
            )) as Box<dyn pipe::Source>
        };

        let mut pipe = DuplexPipe::new(
            (pipe::SimplexDirection::Outgoing, dstr_rx, fwd_tx),
            (pipe::SimplexDirection::Incoming, fwd_rx, dstr_tx),
            update_metrics,
        );

        log_id!(trace, request_id, "TCP connect: pipe exchange started");
        match pipe
            .exchange(context.settings.tcp_connections_timeout)
            .await
        {
            Ok(_) => {
                log_id!(trace, request_id, "TCP connect: pipe closed gracefully");
                Ok(())
            }
            Err(e) => {
                log_id!(trace, request_id, "TCP connect: pipe error: {}", e);
                Err((None, "Error on pipe", ConnectionError::Io(e)))
            }
        }
    }

    async fn on_datagram_mux_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone + Sync>(
        context: Arc<core::Context>,
        forwarder: Arc<dyn Forwarder>,
        request: Box<dyn PendingDatagramMultiplexerRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<
        (),
        (
            Option<Box<dyn PendingDatagramMultiplexerRequest>>,
            &'static str,
            ConnectionError,
        ),
    > {
        let request_id = request.id();
        let client_address = match request.client_address() {
            Ok(x) => x,
            Err(e) => {
                return Err((
                    Some(request),
                    "Failed to get client address",
                    ConnectionError::Io(e),
                ))
            }
        };
        let user_agent = request.user_agent();

        if let Some(auth) = &forwarder_auth {
            let authenticator = forwarder.datagram_mux_authenticator();
            if let Err(e) = authenticator
                .check_auth(
                    client_address,
                    &tls_domain,
                    auth.clone(),
                    user_agent.as_ref().map(String::as_ref),
                )
                .await
            {
                return Err((Some(request), "Failed to authenticate", e));
            }
        }

        let dns_username = username_from_auth(
            forwarder_auth.as_ref(),
            context.authenticator.as_ref().map(|a| a.as_ref()),
        );

        let mut pipe: Box<dyn datagram_pipe::DuplexPipe> = match request.promote_to_next_state() {
            Ok(downstream::DatagramPipeHalves::Udp(dstr_source, dstr_sink)) => {
                let meta = forwarder::UdpMultiplexerMeta {
                    client_address,
                    auth: forwarder_auth,
                    tls_domain,
                    user_agent,
                };
                let (fwd_shared, fwd_source, fwd_sink) = match forwarder
                    .make_udp_datagram_multiplexer(request_id.clone(), meta)
                {
                    Ok(x) => x,
                    Err(e) => {
                        return Err((
                            None,
                            "Failed to create datagram multiplexer",
                            ConnectionError::Io(e),
                        ))
                    }
                };

                let dstr_source = Box::new(DnsPeekSource::new(
                    dstr_source,
                    context.dest_stats.clone(),
                    context.settings.rules_engine.clone(),
                    client_address,
                    dns_username.unwrap_or_default(),
                ))
                    as Box<dyn datagram_pipe::Source<Output = downstream::UdpDatagram>>;

                Box::new(udp_pipe::DuplexPipe::new(
                    (dstr_source, dstr_sink),
                    (fwd_shared, fwd_source, fwd_sink),
                    update_metrics,
                    context.settings.udp_connections_timeout,
                ))
            }
            Ok(downstream::DatagramPipeHalves::Icmp(dstr_source, dstr_sink)) => {
                let (fwd_source, fwd_sink) = match forwarder
                    .make_icmp_datagram_multiplexer(request_id.clone())
                {
                    Ok(Some(x)) => x,
                    Ok(None) => {
                        return Err((
                            None,
                            "ICMP forwarding isn't set up",
                            ConnectionError::Other("Not allowed".to_string()),
                        ))
                    }
                    Err(e) => {
                        return Err((
                            None,
                            "Failed to create datagram multiplexer",
                            ConnectionError::Io(e),
                        ))
                    }
                };

                Box::new(datagram_pipe::GenericDuplexPipe::new(
                    (pipe::SimplexDirection::Outgoing, dstr_source, fwd_sink),
                    (pipe::SimplexDirection::Incoming, fwd_source, dstr_sink),
                    update_metrics,
                ))
            }
            Err(e) => {
                return Err((
                    None,
                    "Failed to respond for datagram multiplexer request",
                    ConnectionError::Io(e),
                ))
            }
        };

        match pipe.exchange().await {
            Ok(_) => {
                log_id!(trace, request_id, "Datagram multiplexer gracefully closed");
                Ok(())
            }
            Err(e) => Err((
                None,
                "Datagram multiplexer closed with error",
                ConnectionError::Io(e),
            )),
        }
    }
}

struct SniPeekSource {
    inner: Box<dyn pipe::Source>,
    dest_stats: Arc<DestinationStats>,
    rules: Option<RulesEngine>,
    client_ip: std::net::IpAddr,
    username: String,
    buf: Vec<u8>,
    done: bool,
}

impl SniPeekSource {
    fn new(
        inner: Box<dyn pipe::Source>,
        dest_stats: Arc<DestinationStats>,
        rules: Option<RulesEngine>,
        client_ip: std::net::IpAddr,
        username: String,
    ) -> Self {
        Self {
            inner,
            dest_stats,
            rules,
            client_ip,
            username,
            buf: Vec::new(),
            done: false,
        }
    }

    fn observe(&mut self, chunk: &[u8]) -> bool {
        if self.done {
            return false;
        }
        let room = dest_stats::TLS_SNI_MAX.saturating_sub(self.buf.len());
        if room == 0 {
            self.done = true;
            self.buf.clear();
            return false;
        }
        self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        match dest_stats::scan_tls_sni(&self.buf) {
            (dest_stats::TlsSniScan::Found, Some(host)) => {
                if !self.username.is_empty() {
                    self.dest_stats.record_host(&self.username, &host);
                }
                self.done = true;
                self.buf.clear();
                self.rules
                    .as_ref()
                    .is_some_and(|e| e.denies_destination(Some(&self.client_ip), &host))
            }
            (dest_stats::TlsSniScan::NeedMore, _) => false,
            _ => {
                self.done = true;
                self.buf.clear();
                false
            }
        }
    }
}

#[async_trait]
impl pipe::Source for SniPeekSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.inner.id()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        let data = self.inner.read().await?;
        if let pipe::Data::Chunk(ref bytes) = data {
            if self.observe(bytes) {
                return Err(io::Error::new(
                    ErrorKind::ConnectionReset,
                    "destination denied",
                ));
            }
        }
        Ok(data)
    }

    fn consume(&mut self, size: usize) -> io::Result<()> {
        self.inner.consume(size)
    }
}

struct DnsPeekSource {
    inner: Box<dyn datagram_pipe::Source<Output = downstream::UdpDatagram>>,
    dest_stats: Arc<DestinationStats>,
    rules: Option<RulesEngine>,
    client_ip: std::net::IpAddr,
    username: String,
}

impl DnsPeekSource {
    fn new(
        inner: Box<dyn datagram_pipe::Source<Output = downstream::UdpDatagram>>,
        dest_stats: Arc<DestinationStats>,
        rules: Option<RulesEngine>,
        client_ip: std::net::IpAddr,
        username: String,
    ) -> Self {
        Self {
            inner,
            dest_stats,
            rules,
            client_ip,
            username,
        }
    }

    fn dns_denied(&self, payload: &[u8]) -> bool {
        let Some(engine) = self.rules.as_ref() else {
            return false;
        };
        dest_stats::dns_question_names(payload)
            .iter()
            .any(|name| engine.denies_destination(Some(&self.client_ip), name))
    }
}

#[async_trait]
impl datagram_pipe::Source for DnsPeekSource {
    type Output = downstream::UdpDatagram;

    fn id(&self) -> log_utils::IdChain<u64> {
        self.inner.id()
    }

    async fn read(&mut self) -> io::Result<Self::Output> {
        loop {
            let datagram = self.inner.read().await?;
            if datagram.meta.destination.port() == net_utils::PLAIN_DNS_PORT_NUMBER {
                if self.dns_denied(&datagram.payload) {
                    continue;
                }
                if !self.username.is_empty() {
                    for name in dest_stats::dns_question_names(&datagram.payload) {
                        self.dest_stats.record_host(&self.username, &name);
                    }
                }
            }
            return Ok(datagram);
        }
    }
}
