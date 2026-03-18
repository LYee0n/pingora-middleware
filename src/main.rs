use pingora_middleware::filters::ProxyMiddleware;
use pingora_middleware::loadbalancer::build_upstream;

use anyhow::Result;
use pingora::prelude::*;
use pingora_load_balancing::{health_check, selection::RoundRobin, LoadBalancer};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .compact()
        .init();

    let mut server = Server::new(Some(Opt::default()))?;
    server.bootstrap();

    let mut upstream = LoadBalancer::<RoundRobin>::try_from_iter(build_upstream(&[
        "intranet-service-1:8080",
        "intranet-service-2:8080",
        "intranet-service-3:8080",
    ]))?;

    let hc = health_check::TcpHealthCheck::new();
    upstream.set_health_check(hc);
    upstream.update_frequency = Some(std::time::Duration::from_secs(5));

    // background_service takes ownership of the LoadBalancer.
    // .task() returns Arc<LoadBalancer<Weighted<RoundRobin>>> — unwrap one Arc layer
    // before passing to ProxyMiddleware::new which expects Arc<LoadBalancer<RoundRobin>>.
    // The Weighted wrapper is transparent for selection so we go through the inner LB.
    let background = background_service("upstream-health-check", upstream);
    let upstream_arc: Arc<LoadBalancer<RoundRobin>> = background.task();
    server.add_service(background);

    let middleware = ProxyMiddleware::new(upstream_arc);
    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, middleware);
    proxy.add_tcp("0.0.0.0:6191");
    server.add_service(proxy);

    info!("Pingora middleware starting on 0.0.0.0:6191");
    server.run_forever();
}
