use tracing::{info, Level};
use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
	tracing_subscriber::fmt()
        .format()
        // Use the environment variable `RUST_LOG` to set the log level, defaulting to `info`
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .init();
}
