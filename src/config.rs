use clap::Parser;

#[derive(Parser)]
pub struct Config {
	#[arg(env = "AMPLITUDE_URL", hide_env = true, short)]
	/// Defaults to env-var of same name
	pub amplitude_url: String,
	#[arg(env = "KAFKA_INGRESS_TOPIC", hide_env = true, short)]
	/// Defaults to env-var of same name
	pub kafka_ingress_topic: String,
	#[arg(env = "PROJECT_KEYS_FILE", hide_env = true, short)]
	/// Defaults to env-var of same name
	pub project_keys_file: String,
}
