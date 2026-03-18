use crate::{
    auth::{has_role, required_roles_for_path, validate_jwt},
    ctx::RequestCtx,
    loadbalancer::canary_peer,
    observability::{inject_trace_headers, log_request},
    rate_limit::RateLimiter,
};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::Error as PingoraError;
use pingora_http::ResponseHeader;
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tracing::{info, warn};

const CANARY_ADDR: &str = "intranet-canary:8080";
const CANARY_FRACTION: f64 = 0.10;

fn internal_token() -> String {
    std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_else(|_| "dev-token".to_string())
}

// Pingora's trait methods return Result<_, Box<pingora::Error>>, not anyhow::Result.
// Define a local alias to keep signatures clean.
type PResult<T> = Result<T, Box<PingoraError>>;

// Convert any error into a boxed pingora::Error
fn to_perr(e: impl std::fmt::Display) -> Box<PingoraError> {
    PingoraError::new_str(Box::leak(e.to_string().into_boxed_str()))
}

pub struct ProxyMiddleware {
    upstream: Arc<LoadBalancer<RoundRobin>>,
    rate_limiter: Arc<RateLimiter>,
}

impl ProxyMiddleware {
    pub fn new(upstream: Arc<LoadBalancer<RoundRobin>>) -> Self {
        Self {
            upstream,
            rate_limiter: Arc::new(RateLimiter::from_env()),
        }
    }
}

#[async_trait]
impl ProxyHttp for ProxyMiddleware {
    type CTX = RequestCtx;
    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::new()
    }

    // ── 1. Request filter ────────────────────────────────────────────────────
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> PResult<bool> {
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();

        let auth_header = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        match validate_jwt(&auth_header) {
            Ok(claims) => {
                if let Some(required) = required_roles_for_path(&path) {
                    if !has_role(&claims.roles, required) {
                        warn!(trace_id = %ctx.trace_id, user_id = %claims.sub, path = %path, "access denied");
                        return respond_with(session, 403, "Forbidden").await;
                    }
                }

                match self.rate_limiter.is_allowed(&claims.sub).await {
                    Ok(false) => {
                        ctx.rate_limited = true;
                        warn!(trace_id = %ctx.trace_id, user_id = %claims.sub, "rate limit exceeded");
                        return respond_with(session, 429, "Too Many Requests").await;
                    }
                    Err(e) => warn!("Rate limiter unavailable, failing open: {e}"),
                    Ok(true) => {}
                }

                ctx.user_id = Some(claims.sub);
                ctx.user_roles = claims.roles;
            }
            Err(e) => {
                warn!(trace_id = %ctx.trace_id, path = %path, "JWT invalid: {e}");
                return respond_with(session, 401, "Unauthorized").await;
            }
        }

        info!(trace_id = %ctx.trace_id, user_id = ?ctx.user_id, method = %method, path = %path, "request accepted");
        Ok(false)
    }

    // ── 2. Upstream peer selection ────────────────────────────────────────────
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> PResult<Box<HttpPeer>> {
        if let Some(uid) = &ctx.user_id {
            if let Some(canary) = canary_peer(uid, CANARY_ADDR, CANARY_FRACTION) {
                ctx.upstream_addr = Some(canary.clone());
                return Ok(Box::new(HttpPeer::new(canary, false, String::new())));
            }
        }

        let upstream = self
            .upstream
            .select(b"", 256)
            .ok_or_else(|| PingoraError::new_str("no healthy upstream"))?;

        let addr = upstream.addr.to_string();
        ctx.upstream_addr = Some(addr.clone());
        Ok(Box::new(HttpPeer::new(addr, false, String::new())))
    }

    // ── 3. Upstream request filter ────────────────────────────────────────────
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()> {
        upstream_request
            .insert_header("x-internal-service-auth", internal_token().as_str())
            .map_err(to_perr)?;

        if let Some(uid) = &ctx.user_id {
            upstream_request.insert_header("x-user-id", uid.as_str()).map_err(to_perr)?;
            upstream_request
                .insert_header("x-user-roles", ctx.user_roles.join(",").as_str())
                .map_err(to_perr)?;
        }

        inject_trace_headers(upstream_request, &ctx.trace_id).map_err(to_perr)?;
        upstream_request.remove_header("authorization");
        Ok(())
    }

    // ── 4. Response filter ────────────────────────────────────────────────────
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()> {
        upstream_response
            .insert_header("x-trace-id", ctx.trace_id.as_str())
            .map_err(to_perr)?;
        upstream_response.remove_header("x-internal-service-auth");
        upstream_response.remove_header("x-upstream-addr");
        Ok(())
    }

    // ── 5. Logging ────────────────────────────────────────────────────────────
    async fn logging(&self, session: &mut Session, _error: Option<&PingoraError>, ctx: &mut Self::CTX) {
        let status = session.response_written().map(|r| r.status.as_u16()).unwrap_or(0);
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();
        log_request(ctx, status, &path, &method);
    }

    // ── 6. Fail to connect ────────────────────────────────────────────────────
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<PingoraError>,
    ) -> Box<PingoraError> {
        warn!(trace_id = %ctx.trace_id, upstream = ?ctx.upstream_addr, "upstream connection failed");
        e
    }
}

async fn respond_with(session: &mut Session, status: u16, message: &str) -> PResult<bool> {
    let body = Bytes::from(format!(r#"{{"error":"{}","status":{}}}"#, message, status));
    let mut resp = ResponseHeader::build(status, None).map_err(to_perr)?;
    resp.insert_header("content-type", "application/json").map_err(to_perr)?;
    resp.insert_header("content-length", body.len().to_string().as_str()).map_err(to_perr)?;
    session.write_response_header(Box::new(resp), false).await.map_err(to_perr)?;
    session.write_response_body(Some(body), true).await.map_err(to_perr)?;
    Ok(true)
}
