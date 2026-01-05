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
	traverse_and_redact_internal(value, None, 0);
}

fn traverse_and_redact_internal(value: &mut Value, parent_key: Option<&str>, depth: usize) {
	match value {
		Value::String(s) => {
			// Special case: at depth == 2 (inside first-level objects like "payload"),
			// if parent_key is exactly "url" or "referrer", parse it and only skip filepath checks for the path part
			if depth == 2 && (parent_key == Some("url") || parent_key == Some("referrer")) {
				*s = redact_url(s).pretty_print();
			} else {
				*s = redact(s, None).pretty_print();
			}
		},
		Value::Array(arr) => {
			for v in arr {
				// Don't pass parent_key to array elements
				traverse_and_redact_internal(v, None, depth + 1);
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
				if key == "idfa"
					|| key == "idfv"
					|| key == "adid"
					|| key == "gaid"
					|| key == "android_id"
					|| key == "aaid"
					|| key == "msai"
					|| key == "advertising_id"
				{
					*v = serde_json::Value::String(Rule::Redact.pretty_print());
				}
				// Only pass the key name if the value is a string (direct child)
				// Don't pass it to nested objects/arrays - they start fresh
				match v {
					Value::String(_) => traverse_and_redact_internal(v, Some(key), depth + 1),
					_ => traverse_and_redact_internal(v, None, depth + 1),
				}
			}
		},

		Value::Number(_) | Value::Bool(_) | Value::Null => {
			// No need to do anything for these types
		},
	}
}

fn redact(s: &str, excluded_labels: Option<&[&str]>) -> Rule {
	// First apply PII redaction with optional exclusions
	let pii_redacted = privacy::redact_pii_with_exclusions(s, excluded_labels);

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

/// Redacts a URL by splitting it into path and query parts,
/// excluding filepath checks for the path but applying them to the query
fn redact_url(url: &str) -> Rule {
	// Find the query string separator
	if let Some(query_start) = url.find('?') {
		let path_part = &url[..query_start];
		let query_part = &url[query_start..]; // includes the '?'

		// Redact path part with filepath exclusion
		let redacted_path = redact(path_part, Some(&["PROXY-FILEPATH"])).pretty_print();

		// Redact query part without exclusions (filepath checks apply here)
		let redacted_query = redact(query_part, None).pretty_print();

		// Combine the results
		Rule::Original(format!("{}{}", redacted_path, redacted_query))
	} else {
		// No query string, so trust the entire URL (exclude filepath checks)
		redact(url, Some(&["PROXY-FILEPATH"]))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use pretty_assertions::assert_eq;

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
			"ip": "10.0.0.1",               // REPLACED with IP of the proxy itself

			"idfa": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",  // REDACTED to [PROXY] (iOS IDFA)
			"idfv": "550E8400-E29B-41D4-A716-446655440000",  // REDACTED to [PROXY] (iOS IDFV)
			"adid": "38400000-8cf0-11bd-b23e-10b96e40000d",  // REDACTED to [PROXY] (Android GAID, alternate key)
			"gaid": "12345678-90ab-cdef-1234-567890abcdef",  // REDACTED to [PROXY] (Google Advertising ID)
			"android_id": "9774d56d682e549c",               // REDACTED to [PROXY] (Android ID - 16 hex chars)
			"aaid": "df07c7dc-cea7-4a89-b328-810ff5acb15d",  // REDACTED to [PROXY] (Amazon Advertising ID)
			"msai": "6F9619FF-8B86-D011-B42D-00C04FC964FF",  // REDACTED to [PROXY] (Microsoft Advertising ID)
			"advertising_id": "00000000-0000-0000-0000-000000000000",  // REDACTED to [PROXY] (opt-out/nil UUID)

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
			"idfv": "[PROXY]",
			"adid": "[PROXY]",
			"gaid": "[PROXY]",
			"android_id": "[PROXY]",
			"aaid": "[PROXY]",
			"msai": "[PROXY]",
			"advertising_id": "[PROXY]",

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
	fn test_traverse_url_special_cases() {
		let mut json_data = json!({
			"payload": {
			  "url": "/path/to/thing?file=/my/secret/file.txt"
			},
		});

		let expected_data = json!({
			"payload": {
			  "url": "/path/to/thing?file=[PROXY-FILEPATH]"
			},
		});

		// Apply the redaction function
		traverse_and_redact(&mut json_data);

		// Assert that the redacted JSON matches the expected output
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_sanctioning() {
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"website": "c2f0a46d-a5b4-4370-8b80-b9b9fcd39f96",
				"hostname": "arbeidsplassen.nav.no",
				"screen": "3440x1440",
				"language": "en-GB",
				"title": "Er du interessert i salg og interiør? - arbeidsplassen.no",
				"url": "https://arbeidsplassen.nav.no/stillinger/stilling/fabaa3cc-90e7-4c00-88aa-ab8d2f9831e8",
				"url2": "fabaa3cc-90e7-4c00-88aa-ab8d2f9831e8_https://arbeidsplassen.nav.no/stillinger/stilling",
				"referrer": ""
			}
		});

		let expected_data = json_data.clone();

		// Apply the redaction function
		traverse_and_redact(&mut json_data);

		// Assert that the JSON remains unchanged (no redaction should occur)
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, Rule::Keep(input.to_string()).pretty_print());
		let input = "test654321";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, Rule::Keep(input.to_string()).pretty_print());
	}

	#[test]
	fn test_redact_regex() {
		let input = "23031510135";
		let result = redact(input, None).pretty_print();
		// This 11-digit number is now caught by the PII Fødselsnummer pattern
		assert_eq!(result, "[PROXY-FNR]");
	}

	#[test]
	fn test_redact_regex_variants() {
		let input = "my_fnr_23031510135";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, "my_fnr_[PROXY-FNR]");

		let input = "my-fnr:23031510135 it's nice";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, "my-fnr:[PROXY-FNR] it's nice");

		let input = "my-fnr-23031510135";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, "my-fnr-[PROXY-FNR]");
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, Rule::Original(input.to_string()).pretty_print());
		let input = "anotherString";
		let result = redact(input, None).pretty_print();
		assert_eq!(result, Rule::Original(input.to_string()).pretty_print());
		let input = "12345";
		let result = redact(input, None).pretty_print();
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

	#[test]
	fn test_advertising_identifiers_redaction() {
		// Test all common advertising identifiers across platforms
		let mut json_data = json!({
			// iOS identifiers
			"idfa": "12345678-1234-1234-1234-123456789012",          // Apple IDFA
			"idfv": "ABCDEF01-2345-6789-ABCD-EF0123456789",          // Apple IDFV

			// Android identifiers
			"gaid": "38400000-8cf0-11bd-b23e-10b96e40000d",          // Google Advertising ID
			"adid": "38400000-8cf0-11bd-b23e-10b96e40000d",          // Alternative GAID field name
			"android_id": "9774d56d682e549c",                        // Android ID (hex string)

			// Other platform identifiers
			"aaid": "87654321-4321-4321-4321-876543210987",          // Amazon Advertising ID
			"msai": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",          // Microsoft Advertising ID

			// Generic field name
			"advertising_id": "00000000-0000-0000-0000-000000000000", // Generic/opted-out

			// Fields that should NOT be redacted
			"api_key": "my-api-key",
			"device_id": "my-device-id",
			"website": "my-website",
			"regular_field": "This is normal text"
		});

		// Expected: all advertising IDs redacted, preserved fields untouched
		let expected_data = json!({
			"idfa": "[PROXY]",
			"idfv": "[PROXY]",
			"gaid": "[PROXY]",
			"adid": "[PROXY]",
			"android_id": "[PROXY]",
			"aaid": "[PROXY]",
			"msai": "[PROXY]",
			"advertising_id": "[PROXY]",
			"api_key": "my-api-key",
			"device_id": "my-device-id",
			"website": "my-website",
			"regular_field": "This is normal text"
		});

		// Apply the redaction function
		traverse_and_redact(&mut json_data);

		// Assert that the redacted JSON matches the expected output
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_filepath_exclusion_for_url_fields() {
		// Test that FILEPATH redaction is excluded only for the top-level "url" field
		// This matches the browser-sent payload structure where url is a raw string
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",       // Should NOT be redacted (url field - exact match)
				"referrer": "/var/www/html/site",             // SHOULD NOT be redacted (also a url field)
				"data": {
					"page_path": "/users/john/profile",       // SHOULD be redacted (not "url")
					"file_path": "C:\\Users\\Admin\\data",    // SHOULD be redacted (not "url")
					"filepath": "/home/user/doc.pdf",         // SHOULD be redacted (not "url")
					"description": "/etc/passwd",             // SHOULD be redacted (not "url")
				}
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",
				"referrer": "/var/www/html/site",
				"data": {
					"page_path": "[PROXY-FILEPATH]",
					"file_path": "[PROXY-FILEPATH]",
					"filepath": "[PROXY-FILEPATH]",
					"description": "[PROXY-FILEPATH]",
				}
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_nested_url_field_does_not_get_exclusion() {
		// Test that only top-level "url" field gets exclusion, not nested "url" fields
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",  // Top-level: should NOT be redacted
				"data": {
					"url": "/var/www/html/index.php",    // Nested: SHOULD be redacted
					"config": {
						"url": "C:\\Users\\Admin\\file.exe"  // Deeply nested: SHOULD be redacted
					}
				}
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",
				"data": {
					"url": "[PROXY-FILEPATH]",
					"config": {
						"url": "[PROXY-FILEPATH]"
					}
				}
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_url_with_query_string_filepath() {
		// Test that filepath checks are applied to query parameters but not the path
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/some/path/page?file=/home/user/secret.txt",  // Path trusted, query checked
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/some/path/page?file=[PROXY-FILEPATH]",
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_url_with_query_string_pii() {
		// Test that PII in query parameters is redacted
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/search?email=user@example.com&phone=98765432",
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/search?email=[PROXY-EMAIL]&phone=[PROXY-PHONE]",
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_url_with_query_string_mixed() {
		// Test mixed PII and filepath in query string
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/api/data?path=/var/log/app.log&ssn=12345678901&redirect=/home/user/file.pdf",
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/api/data?path=[PROXY-FILEPATH]&ssn=[PROXY-FNR]&redirect=[PROXY-FILEPATH]",
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_url_without_query_string() {
		// Test that URLs without query strings have path trusted
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",  // No query, so entire URL is trusted
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/home/user/documents/file.txt",
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_url_path_looks_like_filepath() {
		// Test that path components that look like filepaths are trusted
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"url": "/C:/Users/Admin/page",  // Path looks like Windows path but is trusted
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"url": "/C:/Users/Admin/page",
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_pii_in_url_path_referrer() {
		// Test that PII in the path of a URL (like referrer and url) is redacted
		// while the URL structure itself is preserved (not treated as a filepath)
		let mut json_data = json!({
			"type": "event",
			"payload": {
				"referrer": "https://example.com/path/to/person/johndoe@example.com/mail/view",
				"url": "https://example.com/path/to/person/johndoe@example.com/mail/view"
			}
		});

		let expected_data = json!({
			"type": "event",
			"payload": {
				"referrer": "https://example.com/path/to/person/[PROXY-EMAIL]/mail/view",
				"url": "https://example.com/path/to/person/[PROXY-EMAIL]/mail/view"
			}
		});

		traverse_and_redact(&mut json_data);
		assert_eq!(json_data, expected_data);
	}
}
