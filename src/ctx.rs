/// Per-request context, threaded through every Pingora hook.
///
/// Pingora calls request_filter → upstream_peer → upstream_request_filter →
/// response_filter → logging in order. Use this struct to carry state between
/// those stages without global locks.
#[derive(Default, Debug)]
pub struct RequestCtx {
    /// Distributed trace ID, injected into upstream as X-Trace-Id
    pub trace_id: String,

    /// Validated user identity extracted from JWT
    pub user_id: Option<String>,
    pub user_roles: Vec<String>,

    /// Which upstream instance was selected (for logging)
    pub upstream_addr: Option<String>,

    /// Timestamp the request entered Pingora (for latency metrics)
    pub start_ns: u64,

    /// Whether this request was rate-limited and short-circuited
    pub rate_limited: bool,
}

impl RequestCtx {
    pub fn new() -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            start_ns: current_ns(),
            ..Default::default()
        }
    }

    /// Latency in milliseconds since the request arrived
    pub fn elapsed_ms(&self) -> f64 {
        let elapsed = current_ns().saturating_sub(self.start_ns);
        elapsed as f64 / 1_000_000.0
    }
}

fn current_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
