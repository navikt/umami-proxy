use once_cell::sync::Lazy;

use prometheus::{register_gauge, Gauge, IntCounterVec};
use prometheus::{register_int_counter, register_int_counter_vec, IntCounter};

pub static INCOMING_REQUESTS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("incoming_requests_total", "incoming requests").unwrap());

pub static UPSTREAM_PEER: Lazy<IntCounterVec> =
	Lazy::new(|| register_int_counter_vec!("upstream_peer", "upstream peer", &["peer"]).unwrap());

pub static HANDLED_REQUESTS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("handled_requests_total", "handled requests").unwrap());

pub static PROXY_ERRORS: Lazy<IntCounterVec> = Lazy::new(|| {
	register_int_counter_vec!("proxy_errors_total", "proxys error", &["error"]).unwrap()
});

#[deprecated(
	since = "0.1.0",
	note = "Use `crate::errors::AmplitrudeProxyError` variants & labels put on `PROXY_ERRORS instead`"
)]
pub static CONNECTION_ERRORS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("connection_errors_total", "connection errors").unwrap());

#[deprecated(
	since = "0.1.0",
	note = "Use `crate::errors::AmplitrudeProxyError` variants & labels put on `PROXY_ERRORS instead`"
)]
pub static SSL_ERROR: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("ssl_errors_total", "ssl errors").unwrap());

#[deprecated(
	since = "0.1.0",
	note = "Use `crate::errors::AmplitrudeProxyError` variants & labels put on `PROXY_ERRORS instead`"
)]
pub static BODY_PARSE_ERROR: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("body_parse_error_total", "body parse errors").unwrap());

pub static INVALID_PEER: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("invalid_peer_total", "invalid peer").unwrap());

pub static AMPLITUDE_PEER: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("amplitude_peer_total", "amplitude peer").unwrap());

pub static UMAMI_PEER: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("umami_peer_total", "umami peer").unwrap());

#[deprecated(
	since = "0.1.0",
	note = "Use `crate::errors::AmplitrudeProxyError` variants & labels put on `PROXY_ERRORS instead`"
)]
// co-parsing is serializing
pub static REDACTED_BODY_COPARSE_ERROR: Lazy<IntCounter> = Lazy::new(|| {
	register_int_counter!(
		"redacted_body_coparse_error_total",
		"redact body coparse errors"
	)
	.unwrap()
});

#[deprecated(
	since = "0.1.0",
	note = "Use `crate::errors::AmplitrudeProxyError` variants & labels put on `PROXY_ERRORS instead`"
)]
pub static UPSTREAM_CONNECTION_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
	register_int_counter!(
		"upstream_connection_failures_total",
		"upstream connection failure"
	)
	.unwrap()
});

pub static INGRESS_COUNT: Lazy<Gauge> =
	Lazy::new(|| register_gauge!("ingress_count", "Number of ingresses in the cache").unwrap());
