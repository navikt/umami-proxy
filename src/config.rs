use clap::Parser;

#[derive(Parser, Debug)]
pub struct Config {
	#[arg(env = "UPSTREAM_HOST")]
	pub upstream_host: String,
	#[arg(env = "UPSTREAM_SNI")]
	pub upstream_sni: String,
	#[arg(env = "UPSTREAM_PORT")]
	pub upstream_port: String,
	#[arg(env = "KAFKA_INGRESS_TOPIC")]
	pub kafka_ingress_topic: Option<String>,
	// TODO: Remove optional when confirmed/landed
	#[arg(env = "PROJECT_KEYS_FILE")]
	pub project_keys_file: Option<String>,
	#[arg(env = "DB_PATH")]
	pub db_path: String,
}
