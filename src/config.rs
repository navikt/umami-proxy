use clap::Parser;

#[derive(Parser)]
pub struct Config {
	#[arg(env = "AMPLITUDE_URL", short, default_value = "eu.amplitude.com")]
	/// Defaults to env-var of same name, api.eu.amplitude.com if not set
	pub amplitude_addr: String,
	#[arg(env = "KAFKA_INGRESS_TOPIC", short)]
	/// Defaults to env-var of same name
	pub kafka_ingress_topic: Option<String>,
	#[arg(env = "PROJECT_KEYS_FILE", short)]
	/// Defaults to env-var of same name
	// TODO: Remove optional when confirmed/landed
	pub project_keys_file: Option<String>,
}
