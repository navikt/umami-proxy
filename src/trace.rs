use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub fn init() {
	let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env()) // Reads log level from the `RUST_LOG` env variable
            .finish();

	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed")
}
