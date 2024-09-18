use http::Uri;
use regex::Regex;
use serde_json::{Number, Value};
use std::collections::HashMap as Map;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tra {
	Redacted,           // Replace with the string [Redacted]
	Removed,            // Replace with null
	Kept(String),       // string
	Original(String),   // String
	Annotated(String),  // String
	GeoLocated(String), // Several fields!
}

/// This is a nonserializeable(sic!) Json with redact leaf nodes
pub enum Transform {
	Null,
	Bool(bool),
	Number(Number),
	String(String),
	Transform(Tra),
	Array(Vec<Transform>),
	Object(Map<String, Transform>), // Maybe there should be a note on the keys too?
}

impl Tra {
	pub(crate) fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::Redacted => redacted.to_string(),
			Self::Kept(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
			Self::Annotated(s) => s.to_string(),
			Self::Removed => "".to_string(),
			_ => "".to_string(),
		}
	}
	pub(crate) fn new(s: &str) -> Self {
		redact(s)
	}
}
pub fn traverse_and_redact(value: &mut Value) {
	match value {
		Value::String(s) => {
			*s = redact(s).pretty_print();
		},
		Value::Array(arr) => {
			for v in arr {
				traverse_and_redact(v);
			}
		},
		Value::Object(obj) => {
			for (_, v) in obj.iter_mut() {
				traverse_and_redact(v);
			}
		},
		Value::Number(_) | Value::Bool(_) | Value::Null => {
			// No need to do anything for these types
		},
	}
}

fn redact(s: &str) -> Tra {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		Tra::Kept(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		Tra::Redacted
	} else {
		Tra::Original(s.to_string())
	}
}

fn print_query((key, value): &(Tra, Tra)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<Tra> {
	ps.iter().map(|p: &&str| Tra::new(p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(Tra, Tra)> {
	ss.iter().map(|q| (Tra::new(q.0), Tra::new(q.1))).collect()
}

pub fn redact_uri(old_uri: &Uri) -> Uri {
	let redacted_paths = itertools::join(
		redact_paths(&old_uri.path().split('/').collect::<Vec<_>>())
			.iter()
			.map(|x| x.pretty_print()),
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

#[cfg(test)]
mod tests {
	use super::*;

	use serde_json::json;

	fn test_redact_uuid_in_amplitude_event() {
		// Hardcoded UUID string
		let uuid = "123e4567-e89b-12d3-a456-426614174000";

		// Create a JSON structure similar to an Amplitude event, with the UUID in the "insert_id" field
		let mut json_data = json!({
			"user_id": "12345",
			"device_id": "device-98765",
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
			"event_time": 1678,
			"session_id": 1678,
			"insert_id": uuid,  // The UUID to be redacted
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		// Expected JSON after redaction, where only the "insert_id" field is redacted
		let expected_data = json!({
			"user_id": "12345",
			"device_id": "device-98765",
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
			"event_time": 1678,
			"session_id": 1678,
			"insert_id": "[REDACTED]",  // Only this field is redacted
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		// Apply the redaction function
		traverse_and_redact(&mut json_data);

		// Assert that the redacted JSON matches the expected output
		assert_eq!(json_data, expected_data);
	}
	#[test]
	fn test_redact_location_in_amplitude_event() {
		// TODO
	}

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Kept(input.to_string()).pretty_print());
		let input = "test654321";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Kept(input.to_string()).pretty_print());
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Redacted.pretty_print());
		let input = "1ABCD23456789";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Redacted.pretty_print());
		let input = "123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Redacted.pretty_print());
		let input = "a1b2c3d4e5";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Redacted.pretty_print());
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Original(input.to_string()).pretty_print());
		let input = "anotherString";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Original(input.to_string()).pretty_print());
		let input = "12345";
		let result = redact(input).pretty_print();
		assert_eq!(result, Tra::Original(input.to_string()).pretty_print());
	}
}
