use std::env;

#[derive(Clone, Debug)]
/// Umami Upstream
pub struct Config {
	pub host: String,
	pub sni: Option<String>,
	pub port: String,
}

impl Config {
	pub fn new() -> Self {
		Self {
			host: env::var("UMAMI_HOST").expect("Env var 'UMAMI_HOST' needs to be set"),
			sni: env::var("UMAMI_SNI").ok(),
			port: env::var("UMAMI_PORT").expect("Env var 'UMAMI_PORT' needs to be set"),
		}
	}
}
