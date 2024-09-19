use clap::Parser;

#[derive(Parser, Debug)]
pub struct Config {
	#[arg(
		env = "AMPLITUDE_URL",
		hide_env_values = true,
		short,
		default_value = "eu.amplitude.com"
	)]
	/// Defaults to env-var of same name, has default if not set
	pub amplitude_url: String,

	#[arg(env = "KAFKA_INGRESS_TOPIC", short)]
	/// Defaults to env-var of same name
	pub kafka_ingress_topic: Option<String>,

	#[arg(env = "PROJECT_KEYS_FILE", short)]
	/// Defaults to env-var of same name
	// TODO: Remove optional when confirmed/landed
	pub project_keys_file: Option<String>,

	#[arg(env = "DB_PATH", short)]
	/// Defaults to env-var of same name
	pub db_path: String,
}
