use std::env;

#[derive(Clone, Debug)]
pub struct Upstream {
	pub host: String,
	pub sni: Option<String>,
	pub port: String,
}

#[derive(Clone, Debug)]
pub struct Config {
	pub upstream_amplitude: Upstream,
	pub upstream_umami: Upstream,
}

impl Config {
	pub fn new() -> Self {
		Self {
			upstream_amplitude: Upstream {
				host: env::var("AMPLITUDE_HOST").expect("Env var 'AMPLITUDE_HOST' needs to be set"),
				sni: env::var("AMPLITUDE_SNI").ok(),
				port: env::var("AMPLITUDE_PORT").expect("Env var 'AMPLITUDE_PORT' needs to be set"),
			},
			upstream_umami: Upstream {
				host: env::var("UMAMI_HOST").expect("Env var 'UMAMI_HOST' needs to be set"),
				sni: env::var("UMAMI_SNI").ok(),
				port: env::var("UMAMI_PORT").expect("Env var 'UMAMI_PORT' needs to be set"),
			},
		}
	}
}
