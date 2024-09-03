use clap::*;

use anyhow::Result;

pub struct Config {
	pub amplitude_url: String,
	pub kafka_ingress_topic: String,
	pub project_keys_file: String,
}

impl Config {
	pub fn new() -> Result<Self> {
		Ok(Self {
			amplitude_url: std::env::var("AMPLITUDE_URL")?,
			kafka_ingress_topic: std::env::var("KAFKA_INGRESS_TOPIC")?,
			project_keys_file: std::env::var("PROJECT_KEYS_FILE")?,
		})
	}
}
