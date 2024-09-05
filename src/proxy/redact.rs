use http::Uri;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedactType {
	RedactValue,
	Keep(String),
	Original(String),
}

impl RedactType {
	pub(crate) fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::RedactValue => redacted.to_string(),
			Self::Keep(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
		}
	}
	pub(crate) fn new(s: &str) -> Self {
		redact(s)
	}
}

fn redact(s: &str) -> RedactType {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		RedactType::Keep(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		RedactType::RedactValue
	} else {
		RedactType::Original(s.to_string())
	}
}

fn print_query((key, value): &(RedactType, RedactType)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<RedactType> {
	ps.iter().map(|p: &&str| RedactType::new(p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(RedactType, RedactType)> {
	ss.iter()
		.map(|q| (RedactType::new(q.0), RedactType::new(q.1)))
		.collect()
}

pub fn redact_uri(old_uri: &Uri) -> Uri {
	dbg!(&old_uri);
	let redacted_paths = itertools::join(
		redact_paths(&old_uri.path().split('/').collect::<Vec<_>>())
			.iter()
			.map(|x| {
				// dbg!(x);
				x.pretty_print()
			}),
		"/",
	);

	let redacted_queries = itertools::join(
		redact_queries(
			&old_uri
				.query()
				.unwrap_or("")
				.split('&')
				.flat_map(|q| q.split_once('='))
				.collect::<Vec<_>>(),
		)
		.iter()
		.map(print_query),
		"&",
	);

	let new_uri = format!("{redacted_paths}?{redacted_queries}")
		.parse::<Uri>()
		.unwrap();
	dbg!(&new_uri);
	new_uri
}

pub fn redact_json(value: &mut Value) {
	match value {
		Value::String(s) => {
			*s = redact(s).pretty_print();
		},
		Value::Array(arr) => {
			for v in arr {
				redact_json(v);
			}
		},
		Value::Object(obj) => {
			for (_, v) in obj.iter_mut() {
				redact_json(v);
			}
		},
		_ => {
			// (Number, Bool, Null), do not need redacting (?)
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn test_redact_uuid_in_amplitude_event() {
		let uuid = "123e4567-e89b-12d3-a456-426614174000";

		let mut json_data = json!({
			"user_id": "12345",
			"device_id": "device-98765",  // <- Should this be redacted??
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"page": "signup_page"
			},
			"user_properties": {
				"age": 30,
				"gender": "female",
				"location": "USA"
			},
			"app_version": "1.0.0",
			"platform": "iOS",
			"os_name": "iOS",
			"os_version": "14.4",
			"device_brand": "Apple",
			"device_model": "iPhone 12",
			"event_time": 5,
			"session_id": 5,
			"insert_id": uuid,  // <-- This guy
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		let expected_data = json!({
			"user_id": "12345",
			"device_id": "[redacted]",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"page": "signup_page"
			},
			"user_properties": {
				"age": 30,
				"gender": "female",
				"location": "USA"
			},
			"app_version": "1.0.0",
			"platform": "iOS",
			"os_name": "iOS",
			"os_version": "14.4",
			"device_brand": "Apple",
			"device_model": "iPhone 12",
			"event_time": 5,
			"session_id": 5,
			"insert_id": "[redacted]",
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		redact_json(&mut json_data);

		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input);
		assert_eq!(result, RedactType::Keep(input.to_string()));

		let input = "test654321";
		let result = redact(input);
		assert_eq!(result, RedactType::Keep(input.to_string()));
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "1ABCD23456789";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "123456";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "a1b2c3d4e5";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));

		let input = "anotherString";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));

		let input = "12345";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));
	}
}