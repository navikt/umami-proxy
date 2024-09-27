use std::env;

#[derive(Debug)]
pub struct Config {
	pub upstream_host: String,
	pub upstream_sni: String,
	pub upstream_port: String,
	pub db_path: String,
}

impl Config {
	pub fn new() -> Config {
		Config {
			upstream_host: env::var("UPSTREAM_HOST").unwrap(),
			upstream_sni: env::var("UPSTREAM_SNI").unwrap(),
			upstream_port: env::var("UPSTREAM_PORT").unwrap(),
			db_path: env::var("DB_PATH").unwrap(),
		}
	}
}
