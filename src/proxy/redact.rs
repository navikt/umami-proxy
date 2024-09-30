use std::collections::HashSet;

use http::Uri;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rule {
	Redacted,         // Replace with the string [Redacted]
	Kept(String),     // string
	Original(String), // String
	Drop,             //Drop a field
}

impl Rule {
	pub(crate) fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::Redacted => redacted.to_string(),
			Self::Kept(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
			Self::Drop => "".to_string(),
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
			// Hashset/vec doesn't matter for one element! extremely O(1) lookup either way.
			let fields_to_drop: HashSet<&str> = ["ip_address"].iter().cloned().collect();

			let keys_to_remove: Vec<String> = obj
				.iter()
				.filter(|(key, _v)| fields_to_drop.contains(key.as_str()))
				.map(|(key, _v)| key.clone())
				.collect();

			for key in keys_to_remove {
				dbg!(&key);
				obj.remove(&key);
			}

			for (key, v) in obj.iter_mut() {
				if key == "api_key" {
					continue;
				}
				traverse_and_redact(v);
			}
		},

		Value::Number(_) | Value::Bool(_) | Value::Null => {
			// No need to do anything for these types
		},
	}
}

fn redact(s: &str) -> Rule {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		Rule::Kept(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		Rule::Redacted
	} else {
		Rule::Original(s.to_string())
	}
}

fn print_query((key, value): &(Rule, Rule)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<Rule> {
	ps.iter().map(|p: &&str| Rule::new(p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(Rule, Rule)> {
	ss.iter()
		.map(|q| (Rule::new(q.0), Rule::new(q.1)))
		.collect()
}

pub fn redact_uri(old_uri: &Uri) -> Uri {
	let redacted_paths = itertools::join(
		redact_paths(&old_uri.path().split('/').collect::<Vec<_>>())
			.iter()
			.map(|x| {
				// TODO: THIS IS HECKING HARAM AND THERE IS ACUTALLY ROUTING IN DISGUISE GOING ON HERE, AMPLITUDE SPECIDIFIC
				if *x == Rule::Original("collect".into()) {
					"2/httpapi".into()
				} else {
					x.pretty_print()
				}
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

	let query_params = if old_uri.query().is_some_and(|q| !q.is_empty()) {
		format!("?{redacted_queries}")
	} else {
		String::new()
	};
	let new_uri = format!("{redacted_paths}{query_params}")
		.parse::<Uri>()
		.unwrap();
	dbg!(&new_uri);
	new_uri
}

#[cfg(test)]
mod tests {
	use super::*;

	use serde_json::json;

	#[test]
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
				"event_time": 1678,
				"session_id": 1678,
				"insert_id": "[redacted]",  // Only this field is redacted
				"location_lat": 37.7749,
				"location_lng": -122.4194,
		//		"ip_address": "123.45.67.89"   // Ip Address gets deleted
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
		assert_eq!(result, Rule::Kept(input.to_string()).pretty_print());
		let input = "test654321";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Kept(input.to_string()).pretty_print());
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Redacted.pretty_print());
		let input = "1ABCD23456789";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Redacted.pretty_print());
		let input = "123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Redacted.pretty_print());
		let input = "a1b2c3d4e5";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Redacted.pretty_print());
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Original(input.to_string()).pretty_print());
		let input = "anotherString";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Original(input.to_string()).pretty_print());
		let input = "12345";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Original(input.to_string()).pretty_print());
	}
}
