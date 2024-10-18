use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
	Redact,             // Replace the string w/[Redacted]
	RedactSsns(String), // Replace SSN substrings with the string [Redacted]
	Keep(String),
	Original(String),
	Obfuscate(String), // Remove client IP, replace w/ours
}

static KEEP_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
	Regex::new(r"((nav|test)[0-9]{6})").expect("Hard-coded regex expression should be valid")
});
static HEX_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
	Regex::new(r"[a-f0-9\-]{6,}").expect("Hard-coded regex expression should be valid")
});
static ID_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
	Regex::new(r"\d[oiA-Z0-9]{8,}").expect("Hard-coded regex expression should be valid")
});

impl Rule {
	pub fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::RedactSsns(s) => {
				let mut new = s.to_string();
				new = HEX_REGEX.replace_all(&new, redacted).to_string();
				new = ID_REGEX.replace_all(&new, redacted).to_string();
				new
			},
			Self::Keep(s) | Self::Original(s) | Self::Obfuscate(s) => s.to_string(),
			Self::Redact => redacted.to_string(),
		}
	}
}

// This function should be split into two functions
// one for           Value -> Extended_Value_With_Rule_Nodes and
// one function for  Extended_Value_With_Rule_Nodes -> Value
// So that
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
			let fields_to_drop: HashSet<&str> = std::iter::once(&"ip_address").copied().collect();

			let keys_to_remove: Vec<String> = obj
				.iter()
				.filter(|(key, _v)| fields_to_drop.contains(key.as_str()))
				.map(|(key, _v)| key.clone())
				.collect();

			for key in keys_to_remove {
				obj.remove(&key);
			}

			for (key, v) in obj.iter_mut() {
				if key == "api_key" || key == "device_id" || key == "website" {
					continue;
				}
				if key == "ip" {
					*v = serde_json::Value::String(
						Rule::Obfuscate(String::from("$remote")).pretty_print(),
					);
				}
				if key == "idfa" || key == "idfv" || key == "adid" || key == "android_id" {
					*v = serde_json::Value::String(Rule::Redact.pretty_print());
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
	if KEEP_REGEX.is_match(s) {
		Rule::Keep(s.to_string())
	} else if HEX_REGEX.is_match(s) || ID_REGEX.is_match(s) {
		Rule::RedactSsns(s.to_string())
	} else {
		Rule::Original(s.to_string())
	}
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
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Keep(input.to_string()).pretty_print());
		let input = "test654321";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::Keep(input.to_string()).pretty_print());
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::RedactSsns(input.to_string()).pretty_print());
		let input = "1ABCD23456789";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::RedactSsns(input.to_string()).pretty_print());
		let input = "123456";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::RedactSsns(input.to_string()).pretty_print());
		let input = "a1b2c3d4e5";
		let result = redact(input).pretty_print();
		assert_eq!(result, Rule::RedactSsns(input.to_string()).pretty_print());
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
