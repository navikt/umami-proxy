use std::env;

#[derive(Clone, Debug)]
/// Umami Upstream
pub struct Config {
	pub host: String,
	pub sni: Option<String>,
	pub port: String,
	pub proxy_listen_port: u16,
	pub probe_listen_port: u16,
	pub metrics_listen_port: u16,
	pub disable_k8s: bool,
}

impl Config {
	pub fn new() -> Self {
		// Provide soft defaults for local dev so the binary can start with only a `.env` copied from `.env.example`.
		let host = env::var("UMAMI_HOST").unwrap_or_else(|_| "localhost".into());
		let port = env::var("UMAMI_PORT").unwrap_or_else(|_| "1234".into());
		let sni = env::var("UMAMI_SNI").ok().filter(|s| !s.is_empty());
		let proxy_listen_port = env::var("PROXY_LISTEN_PORT")
			.ok()
			.and_then(|p| p.parse().ok())
			.unwrap_or(6191);
		let probe_listen_port = env::var("PROBE_LISTEN_PORT")
			.ok()
			.and_then(|p| p.parse().ok())
			.unwrap_or(6969);
		let metrics_listen_port = env::var("METRICS_LISTEN_PORT")
			.ok()
			.and_then(|p| p.parse().ok())
			.unwrap_or(9090);
		let disable_k8s = env::var("DISABLE_K8S").map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
			.unwrap_or(false);
		Self { host, sni, port, proxy_listen_port, probe_listen_port, metrics_listen_port, disable_k8s }
	}
}
