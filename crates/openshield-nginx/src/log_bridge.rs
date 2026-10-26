//! Sends the core's `log` records to nginx's error log.

use log::{Level, LevelFilter, Log, Metadata, Record};
use ngx::ffi::{NGX_LOG_DEBUG, NGX_LOG_ERR, NGX_LOG_INFO, NGX_LOG_WARN, ngx_cycle};
use ngx::ngx_log_error;

struct NginxLog;

impl Log for NginxLog {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let level = match record.level() {
            Level::Error => NGX_LOG_ERR,
            Level::Warn => NGX_LOG_WARN,
            Level::Info => NGX_LOG_INFO,
            Level::Debug | Level::Trace => NGX_LOG_DEBUG,
        };
        let log = unsafe { (*ngx_cycle).log };
        if log.is_null() {
            return;
        }
        ngx_log_error!(level, log, "openshield: {}", record.args());
    }

    fn flush(&self) {}
}

static LOGGER: NginxLog = NginxLog;

/// Route `log` output to nginx. Safe to call more than once (reloads).
pub fn install() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Info);
    }
}
