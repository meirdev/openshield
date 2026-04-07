#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod challenge;
mod compiler;
mod config;
mod geoip;
mod logging;
mod proxy;
mod reload;
mod waf;

use std::sync::{Arc, RwLock};

use clap::Parser;
use config::Config;
use log::{error, info};
use pingora::apps::prometheus_http_app::PrometheusServer;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::services::listening::Service as ListeningService;

#[derive(Parser)]
#[command(name = "openshield", version, about = "OpenShield proxy")]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    config: std::path::PathBuf,
}

fn parse_upstream(addr: &str) -> (String, u16, bool) {
    let (addr, tls) = if let Some(rest) = addr.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = addr.strip_prefix("http://") {
        (rest, false)
    } else {
        (addr, false)
    };
    let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().expect("invalid port"))
    } else if tls {
        (addr.to_string(), 443)
    } else {
        (addr.to_string(), 80)
    };
    (host, port, tls)
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("openshield=info,pingora=info"),
    )
    .format_timestamp_millis()
    .init();

    let cli = Cli::parse();

    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {:?}: {}", cli.config, e);
            std::process::exit(1);
        }
    };
    info!("Config loaded from {:?}", cli.config);

    // GeoIP (optional)
    let geoip = config.geoip.as_ref().map(|geo_cfg| {
        let g = geoip::GeoIp::open(&geo_cfg.city_mmdb, &geo_cfg.asn_mmdb)
            .expect("Failed to open MaxMind databases");
        info!(
            "GeoIP loaded: city={:?}, asn={:?}",
            geo_cfg.city_mmdb, geo_cfg.asn_mmdb
        );
        g
    });
    let geoip = Arc::new(RwLock::new(geoip));

    // WAF scheme + engine
    let scheme = Arc::new(waf::scheme::build(&config.scores));
    info!("WAF scheme: {} fields", scheme.field_count());

    let engine = match compiler::compile(&config, &scheme, None) {
        Ok(e) => Arc::new(RwLock::new(e)),
        Err(e) => {
            error!("Failed to compile rules: {}", e);
            std::process::exit(1);
        }
    };

    // Lists
    let (ip_lists, bytes_lists) = waf::lists::build_from_config(&config.lists);
    let ip_lists = Arc::new(RwLock::new(ip_lists));
    let bytes_lists = Arc::new(RwLock::new(bytes_lists));

    // Logger
    let logger = Arc::new(logging::Logger::new(&config.logging));
    info!(
        "Logging: access={:?}, audit={:?}, format={}",
        config.logging.access_log, config.logging.audit_log, config.logging.format
    );

    // Challenge
    let challenge = config.challenge.as_ref().map(|cfg| {
        info!("Challenge page enabled (Turnstile)");
        Arc::new(challenge::ChallengeManager::new(cfg))
    });

    // Upstream
    let (upstream_host, upstream_port, upstream_tls) = parse_upstream(&config.upstream);
    info!(
        "Reverse proxy: {} -> {}:{} (tls={})",
        config.listen, &upstream_host, upstream_port, upstream_tls
    );

    // Server
    let mut conf = pingora::server::configuration::ServerConf::default();
    conf.threads = config.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    if let Some(pool_size) = config.upstream_keepalive_pool {
        conf.upstream_keepalive_pool_size = pool_size;
    }
    info!(
        "Worker threads: {}, upstream keepalive pool: {}",
        conf.threads, conf.upstream_keepalive_pool_size
    );
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let handler = proxy::ReverseProxyHandler {
        upstream_tls,
        upstream_host,
        upstream_port,
        geoip: geoip.clone(),
        scheme: scheme.clone(),
        engine: engine.clone(),
        max_request_body_buffer: config.max_request_body_buffer,
        inspect_response_body: config.inspect_response_body,
        max_response_body_buffer: config.max_response_body_buffer,
        ip_lists: ip_lists.clone(),
        bytes_lists: bytes_lists.clone(),
        challenge,
        logger,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, handler);
    if let Some(ref tls_cfg) = config.tls {
        use pingora::listeners::tls::TlsSettings;
        let mut tls_settings = TlsSettings::intermediate(
            tls_cfg.cert.to_str().expect("invalid cert path"),
            tls_cfg.key.to_str().expect("invalid key path"),
        )
        .expect("Failed to load TLS cert/key");
        tls_settings.enable_h2();
        proxy_service.add_tls_with_settings(&config.listen, None, tls_settings);
        info!("Listening on {} (TLS)", config.listen);
    } else {
        proxy_service.add_tcp(&config.listen);
        info!("Listening on {} (plain HTTP)", config.listen);
    }
    server.add_service(proxy_service);

    if let Some(ref metrics_cfg) = config.metrics {
        if metrics_cfg.enabled {
            let mut prom_service = ListeningService::<PrometheusServer>::prometheus_http_service();
            prom_service.add_tcp(&metrics_cfg.listen);
            server.add_service(prom_service);
            info!("Prometheus metrics at {}", metrics_cfg.listen);
        }
    }

    reload::start_reload_listener(
        cli.config.clone(),
        scheme,
        engine,
        ip_lists,
        bytes_lists,
        geoip,
    );

    server.run_forever();
}
