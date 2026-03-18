use crate::ctx::RequestCtx;
use tracing::{error, info, warn};

/// Logs a structured access line once the response is complete.
///
/// In production, replace this with an OpenTelemetry span exporter. The
/// fields here map 1-to-1 with OTel semantic conventions so the migration
/// is mechanical: swap `tracing::info!` for `span.set_attribute(...)`.
pub fn log_request(ctx: &RequestCtx, status: u16, path: &str, method: &str) {
    let elapsed = ctx.elapsed_ms();

    if ctx.rate_limited {
        warn!(
            trace_id = %ctx.trace_id,
            user_id  = ?ctx.user_id,
            path     = %path,
            method   = %method,
            status   = %status,
            latency_ms = %elapsed,
            "request rate-limited"
        );
        return;
    }

    if status >= 500 {
        error!(
            trace_id  = %ctx.trace_id,
            user_id   = ?ctx.user_id,
            upstream  = ?ctx.upstream_addr,
            path      = %path,
            method    = %method,
            status    = %status,
            latency_ms = %elapsed,
            "upstream error"
        );
    } else {
        info!(
            trace_id  = %ctx.trace_id,
            user_id   = ?ctx.user_id,
            upstream  = ?ctx.upstream_addr,
            path      = %path,
            method    = %method,
            status    = %status,
            latency_ms = %elapsed,
            "request complete"
        );
    }
}

/// Injects trace propagation headers into upstream requests.
///
/// Conforms to the W3C Trace Context specification so downstream services
/// can join the same trace in Jaeger / Tempo / Honeycomb without extra config.
pub fn inject_trace_headers(
    headers: &mut pingora_http::RequestHeader,
    trace_id: &str,
) -> anyhow::Result<()> {
    // W3C traceparent: version-trace_id-parent_id-flags
    let parent_id = &trace_id[..16.min(trace_id.len())];
    let traceparent = format!("00-{trace_id}-{parent_id}-01");
    headers.insert_header("traceparent", &traceparent)?;

    // Also propagate as a simpler custom header for services that read it directly
    headers.insert_header("x-trace-id", trace_id)?;
    Ok(())
}
