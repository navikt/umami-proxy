use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use super::privacy;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
	Redact,             // Replace the string w/[PROXY]
	RedactSsns(String), // Replace SSN substrings with the string [PROXY]
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
		let redacted = "[PROXY]";
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
	fn test_redact_comprehensive_umami_event() {
		// Create a comprehensive JSON structure demonstrating all redaction rules
		let mut json_data = json!({
			"payload": {
				"hostname": "https://example.nav.no",
				"website": "my-website-id"  // PRESERVED (never redacted)
			},
			"api_key": "abc123",          // PRESERVED (never redacted)
			"device_id": "device-123",    // PRESERVED (never redacted)

			"user_email": "john.doe@example.com",  // REDACTED to [PROXY-EMAIL]
			"user_ssn": "12345678901",             // REDACTED to [PROXY-FNR]
			"phone": "98765432",                   // REDACTED to [PROXY-PHONE]
			"navident": "X123456",                 // REDACTED to [PROXY-NAVIDENT]

			"ip_address": "192.168.1.100",  // REMOVED ENTIRELY
			"ip": "10.0.0.1",               // REPLACED with "$remote"

			"idfa": "ABCD-1234-EFGH-5678",  // REDACTED to [PROXY]

			"account_number": "1234.56.78901",  // REDACTED to [PROXY-ACCOUNT]
			"license_plate": "AB12345",         // REDACTED to [PROXY-LICENSE-PLATE]
			"org_number": "123456789",          // REDACTED to [PROXY-ORG-NUMBER]

			"file_path": "/home/john/Documents/secret.pdf",  // REDACTED to [PROXY-FILEPATH]
			"name": "John Doe",                              // REDACTED to [PROXY-NAME]
			"address": "0123 Oslo",                          // REDACTED to [PROXY-ADDRESS]

			"uuid": "550e8400-e29b-41d4-a716-446655440000",  // PRESERVED
			"website_url": "https://example.com/page",       // PRESERVED

			"event_properties": {
				"regular_text": "This is fine"  // UNCHANGED
			}
		});

		// Expected JSON after redaction
		let expected_data = json!({
			"payload": {
				"hostname": "https://example.nav.no",
				"website": "my-website-id"
			},
			"api_key": "abc123",
			"device_id": "device-123",

			"user_email": "[PROXY-EMAIL]",
			"user_ssn": "[PROXY-FNR]",
			"phone": "[PROXY-PHONE]",
			"navident": "[PROXY-NAVIDENT]",

			// ip_address is removed entirely
			"ip": "$remote",

			"idfa": "[PROXY]",

			"account_number": "[PROXY-ACCOUNT]",
			"license_plate": "[PROXY-LICENSE-PLATE]",
			"org_number": "[PROXY-ORG-NUMBER]",

			"file_path": "[PROXY-FILEPATH]",
			"name": "[PROXY-NAME]",
			"address": "[PROXY-ADDRESS]",

			"uuid": "550e8400-e29b-41d4-a716-446655440000",
			"website_url": "https://example.com/page",

			"event_properties": {
				"regular_text": "This is fine"
			}
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
	fn test_redact_regex_variants() {
		let input = "my_fnr_23031510135";
		let result = redact(input).pretty_print();
		assert_eq!(result, "my_fnr_[PROXY-FNR]");

		let input = "my-fnr:23031510135 it's nice";
		let result = redact(input).pretty_print();
		assert_eq!(result, "my-fnr:[PROXY-FNR] it's nice");

		let input = "my-fnr-23031510135";
		let result = redact(input).pretty_print();
		assert_eq!(result, "my-fnr-[PROXY-FNR]");
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
