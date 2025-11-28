use std::env;

#[derive(Clone, Debug)]
/// Umami Upstream
pub struct Config {
	pub host: String,
	pub sni: Option<String>,
	pub port: String,
	pub path: Option<String>,
}

impl Config {
	pub fn new() -> Self {
		Self {
			host: env::var("UMAMI_HOST").expect("Env var 'UMAMI_HOST' needs to be set"),
			sni: env::var("UMAMI_SNI").ok(),
			port: env::var("UMAMI_PORT").expect("Env var 'UMAMI_PORT' needs to be set"),
			path: env::var("UMAMI_PATH").ok(),
		}
	}
}
