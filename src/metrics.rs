use once_cell::sync::Lazy;
use prometheus::{register_int_counter, IntCounter};

pub static INCOMING_REQUESTS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("incoming_requests_total", "incoming requests").unwrap());

pub static HANDLED_REQUESTS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("handled_requests_total", "handled requests").unwrap());

pub static ERRORS_WHILE_PROXY: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("error_while_proxy_total", "error while proxy").unwrap());

pub static CONNECTION_ERRORS: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("connection_errors_total", "connection errors").unwrap());

pub static SSL_ERROR: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("ssl_errors_total", "ssl errors").unwrap());

pub static BODY_PARSE_ERROR: Lazy<IntCounter> =
	Lazy::new(|| register_int_counter!("body_parse_error_total", "body parse errors").unwrap());

pub static REDACTED_BODY_COPARSE_ERROR: Lazy<IntCounter> = Lazy::new(|| {
	register_int_counter!(
		"redacted_body_coparse_error_total",
		"redact body coparse errors"
	)
	.unwrap()
});

pub static UPSTREAM_CONNECTION_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
	register_int_counter!(
		"upstream_connection_failures_total",
		"upstream connection failure"
	)
	.unwrap()
});
