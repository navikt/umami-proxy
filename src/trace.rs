use std::io::IsTerminal;

use tracing::{level_filters::LevelFilter, Level, Subscriber};
use tracing_subscriber::{filter, fmt, layer::SubscriberExt, Layer};

pub fn configure_logging() -> impl Subscriber {
	let log_level = LevelFilter::INFO;

	let (plain_log_format, json_log_format) = if std::io::stdout().is_terminal() {
		(Some(fmt::layer().pretty().with_filter(log_level)), None)
	} else {
		(
			None,
			Some(
				fmt::layer()
					.json()
					.flatten_event(true)
					.with_filter(log_level),
			),
		)
	};

	tracing_subscriber::registry()
		.with(plain_log_format)
		.with(json_log_format)
		.with(
			filter::Targets::new()
				.with_default(log_level)
				.with_target("axum::rejection", Level::TRACE)
				.with_target("hyper", Level::ERROR)
				.with_target("hyper_util", Level::ERROR)
				.with_target("reqwest", Level::WARN)
				.with_target("tower", Level::ERROR),
		)
}
