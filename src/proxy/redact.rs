use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use super::privacy;

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
static FNR_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
	Regex::new(r"\b\d{6}\d{5}\b").expect("Hard-coded regex expression should be valid")
});

impl Rule {
	pub fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::RedactSsns(s) => {
				let mut new = s.to_string();
				new = FNR_REGEX.replace_all(&new, redacted).to_string();
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
	// First apply PII redaction
	let pii_redacted = privacy::redact_pii(s);

	// If PII was found and redacted, return that
	if pii_redacted != s {
		return Rule::Original(pii_redacted);
	}

	// Otherwise, apply the original redaction logic
	if KEEP_REGEX.is_match(s) {
		Rule::Keep(s.to_string())
	} else if FNR_REGEX.is_match(s) {
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
		let uuid = "23031510135";

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
			"insert_id": "[PROXY-FNR]",  // Now caught by PII filter
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
		let input = "23031510135";
		let result = redact(input).pretty_print();
		// This 11-digit number is now caught by the PII Fødselsnummer pattern
		assert_eq!(result, "[PROXY-FNR]");
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

	#[test]
	fn test_comprehensive_pii_redaction() {
		// Create a JSON structure with various PII types
		let mut json_data = json!({
			"user_email": "user@example.com",
			"user_id": "550e8400-e29b-41d4-a716-446655440000",
			"ssn": "12345678901",
			"phone": "98765432",
			"ip_address": "192.168.1.1",
			"event_properties": {
				"card_number": "1234 5678 9012 3456",
				"account": "1234.56.78901",
				"navident": "X123456",
				"regular_field": "This is normal text"
			}
		});

		// Expected JSON after redaction
		// Note: ip_address field is removed by traverse_and_redact
		// Note: UUID and card number filters have been removed (no longer redacted)
		let expected_data = json!({
			"user_email": "[PROXY-EMAIL]",
			"user_id": "550e8400-e29b-41d4-a716-446655440000",
			"ssn": "[PROXY-FNR]",
			"phone": "[PROXY-PHONE]",
			"event_properties": {
				"card_number": "1234 5678 9012 3456",
				"account": "[PROXY-ACCOUNT]",
				"navident": "[PROXY-NAVIDENT]",
				"regular_field": "This is normal text"
			}
		});

		// Apply the redaction function
		traverse_and_redact(&mut json_data);

		// Assert that the redacted JSON matches the expected output
		assert_eq!(json_data, expected_data);
	}
}
