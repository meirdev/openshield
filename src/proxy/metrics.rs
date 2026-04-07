use prometheus::{IntCounter, IntGauge, register_int_counter, register_int_gauge};

lazy_static::lazy_static! {
    pub static ref TOTAL_REQUESTS: IntCounter =
        register_int_counter!("openshield_requests_total", "Total HTTP requests processed").unwrap();
    pub static ref ACTIVE_CONNECTIONS: IntGauge =
        register_int_gauge!("openshield_connections_active", "Currently active connections").unwrap();
    pub static ref BYTES_RECEIVED: IntCounter =
        register_int_counter!("openshield_bytes_received_total", "Total bytes received from clients").unwrap();
    pub static ref BYTES_SENT: IntCounter =
        register_int_counter!("openshield_bytes_sent_total", "Total bytes sent to clients").unwrap();
}
