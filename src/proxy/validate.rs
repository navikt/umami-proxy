use serde_json::Value;

const MAX_FIELD_LENGTH: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldViolation {
	pub path: String,
	pub length: usize,
}

impl FieldViolation {
	pub fn new(path: String, length: usize) -> Self {
		Self { path, length }
	}
}

/// Validates that all string fields in the JSON value are within the maximum field length.
/// Returns a list of violations if any field exceeds the limit.
pub fn validate_field_lengths(value: &Value) -> Result<(), Vec<FieldViolation>> {
	let mut violations = Vec::new();
	traverse_and_validate(value, String::new(), &mut violations);

	if violations.is_empty() {
		Ok(())
	} else {
		Err(violations)
	}
}

fn traverse_and_validate(
	value: &Value,
	current_path: String,
	violations: &mut Vec<FieldViolation>,
) {
	match value {
		Value::String(s) => {
			if s.len() > MAX_FIELD_LENGTH {
				violations.push(FieldViolation::new(current_path, s.len()));
			}
		},
		Value::Array(arr) => {
			for (index, v) in arr.iter().enumerate() {
				let path = if current_path.is_empty() {
					format!("[{}]", index)
				} else {
					format!("{}[{}]", current_path, index)
				};
				traverse_and_validate(v, path, violations);
			}
		},
		Value::Object(obj) => {
			for (key, v) in obj.iter() {
				let path = if current_path.is_empty() {
					key.clone()
				} else {
					format!("{}.{}", current_path, key)
				};
				traverse_and_validate(v, path, violations);
			}
		},
		Value::Number(_) | Value::Bool(_) | Value::Null => {
			// No validation needed for these types
		},
	}
}

/// Validates and filters out fields that exceed the maximum length.
/// Returns a tuple of (filtered_value, violations).
/// The filtered value has all offending fields removed.
pub fn validate_and_filter(value: &Value) -> (Value, Vec<FieldViolation>) {
	let mut violations = Vec::new();
	let filtered = filter_long_fields(value, String::new(), &mut violations);
	(filtered, violations)
}

/// Recursively filters out string fields that exceed the maximum length.
/// Collects violations along the way.
fn filter_long_fields(
	value: &Value,
	current_path: String,
	violations: &mut Vec<FieldViolation>,
) -> Value {
	match value {
		Value::String(s) => {
			if s.len() > MAX_FIELD_LENGTH {
				violations.push(FieldViolation::new(current_path, s.len()));
				// Return null for fields that are too long (they will be removed from objects)
				Value::Null
			} else {
				value.clone()
			}
		},
		Value::Array(arr) => {
			let filtered_array: Vec<Value> = arr
				.iter()
				.enumerate()
				.map(|(index, v)| {
					let path = if current_path.is_empty() {
						format!("[{}]", index)
					} else {
						format!("{}[{}]", current_path, index)
					};
					filter_long_fields(v, path, violations)
				})
				.filter(|v| !v.is_null() || matches!(value, Value::Array(_)))
				.collect();
			Value::Array(filtered_array)
		},
		Value::Object(obj) => {
			let filtered_object: serde_json::Map<String, Value> = obj
				.iter()
				.filter_map(|(key, v)| {
					let path = if current_path.is_empty() {
						key.clone()
					} else {
						format!("{}.{}", current_path, key)
					};
					let filtered_value = filter_long_fields(v, path, violations);
					// Remove fields that became null due to being too long
					if filtered_value.is_null() && v.is_string() {
						None
					} else {
						Some((key.clone(), filtered_value))
					}
				})
				.collect();
			Value::Object(filtered_object)
		},
		Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
	}
}

/// Formats violations into a human-readable error message
pub fn format_error_message(violations: &[FieldViolation]) -> String {
	let mut message = format!(
		"Field length validation failed. The following {} field(s) exceed the {} character limit:\n",
		violations.len(),
		MAX_FIELD_LENGTH
	);
	
	for violation in violations {
		message.push_str(&format!(
			"  - '{}': {} characters\n",
			violation.path, violation.length
		));
	}
	
	message
}

/// Creates a JSON error response for field length violations
pub fn create_error_response(violations: &[FieldViolation]) -> Value {
	serde_json::json!({
		"error": "Field length validation failed",
		"message": format!(
			"{} field(s) exceed the {} character limit",
			violations.len(),
			MAX_FIELD_LENGTH
		),
		"limit": MAX_FIELD_LENGTH,
		"violations": violations.iter().map(|v| {
			serde_json::json!({
				"field": v.path,
				"length": v.length
			})
		}).collect::<Vec<_>>()
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn test_validate_short_strings() {
		let data = json!({
			"name": "John Doe",
			"description": "A short description"
		});

		assert!(validate_field_lengths(&data).is_ok());
	}

	#[test]
	fn test_validate_exactly_500_chars() {
		let exactly_500 = "a".repeat(500);
		let data = json!({
			"description": exactly_500
		});

		assert!(validate_field_lengths(&data).is_ok());
	}

	#[test]
	fn test_validate_over_500_chars() {
		let over_500 = "a".repeat(501);
		let data = json!({
			"description": over_500.clone()
		});

		let result = validate_field_lengths(&data);
		assert!(result.is_err());

		let violations = result.unwrap_err();
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "description");
		assert_eq!(violations[0].length, 501);
	}

	#[test]
	fn test_validate_nested_objects() {
		let over_500 = "b".repeat(550);
		let data = json!({
			"user": {
				"profile": {
					"bio": over_500.clone()
				}
			}
		});

		let result = validate_field_lengths(&data);
		assert!(result.is_err());

		let violations = result.unwrap_err();
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "user.profile.bio");
		assert_eq!(violations[0].length, 550);
	}

	#[test]
	fn test_validate_arrays() {
		let over_500 = "c".repeat(600);
		let data = json!({
			"items": [
				"valid string",
				over_500.clone(),
				"another valid"
			]
		});

		let result = validate_field_lengths(&data);
		assert!(result.is_err());

		let violations = result.unwrap_err();
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "items[1]");
		assert_eq!(violations[0].length, 600);
	}

	#[test]
	fn test_validate_multiple_violations() {
		let over_500_1 = "d".repeat(510);
		let over_500_2 = "e".repeat(520);
		let data = json!({
			"field1": over_500_1.clone(),
			"nested": {
				"field2": over_500_2.clone()
			}
		});

		let result = validate_field_lengths(&data);
		assert!(result.is_err());

		let violations = result.unwrap_err();
		assert_eq!(violations.len(), 2);

		// Check both violations are present
		assert!(violations
			.iter()
			.any(|v| v.path == "field1" && v.length == 510));
		assert!(violations
			.iter()
			.any(|v| v.path == "nested.field2" && v.length == 520));
	}

	#[test]
	fn test_validate_non_string_types() {
		let data = json!({
			"number": 12345,
			"boolean": true,
			"null_value": null,
			"array_of_numbers": [1, 2, 3],
			"valid_string": "short"
		});

		assert!(validate_field_lengths(&data).is_ok());
	}

	#[test]
	fn test_format_error_message() {
		let violations = vec![
			FieldViolation::new("field1".to_string(), 510),
			FieldViolation::new("nested.field2".to_string(), 520),
		];

		let message = format_error_message(&violations);

		assert!(message.contains("Field length validation failed"));
		assert!(message.contains("2 field(s)"));
		assert!(message.contains("500 character limit"));
		assert!(message.contains("field1"));
		assert!(message.contains("510 characters"));
		assert!(message.contains("nested.field2"));
		assert!(message.contains("520 characters"));
	}

	#[test]
	fn test_create_error_response() {
		let violations = vec![FieldViolation::new("field1".to_string(), 510)];

		let response = create_error_response(&violations);

		assert_eq!(response["error"], "Field length validation failed");
		assert_eq!(response["limit"], 500);
		assert_eq!(response["violations"][0]["field"], "field1");
		assert_eq!(response["violations"][0]["length"], 510);
	}

	#[test]
	fn test_complex_nested_structure() {
		let over_500 = "x".repeat(505);
		let data = json!({
			"payload": {
				"events": [
					{
						"event_properties": {
							"description": over_500.clone()
						}
					}
				]
			}
		});

		let result = validate_field_lengths(&data);
		assert!(result.is_err());

		let violations = result.unwrap_err();
		assert_eq!(violations.len(), 1);
		assert_eq!(
			violations[0].path,
			"payload.events[0].event_properties.description"
		);
		assert_eq!(violations[0].length, 505);
	}

	// Tests for filtering behavior
	#[test]
	fn test_filter_removes_long_field() {
		let over_500 = "a".repeat(510);
		let data = json!({
			"short_field": "valid",
			"long_field": over_500.clone()
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// Should have one violation
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "long_field");
		assert_eq!(violations[0].length, 510);
		
		// Filtered data should only have the short field
		assert_eq!(filtered["short_field"], "valid");
		assert!(filtered.get("long_field").is_none());
	}

	#[test]
	fn test_filter_preserves_valid_fields() {
		let data = json!({
			"field1": "short",
			"field2": "another short one",
			"nested": {
				"field3": "also valid"
			}
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// No violations
		assert!(violations.is_empty());
		
		// All fields preserved
		assert_eq!(filtered, data);
	}

	#[test]
	fn test_filter_nested_objects() {
		let over_500 = "b".repeat(520);
		let data = json!({
			"user": {
				"name": "John",
				"bio": over_500.clone(),
				"email": "john@example.com"
			}
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// Should have one violation
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "user.bio");
		
		// Filtered should have user object without bio
		assert_eq!(filtered["user"]["name"], "John");
		assert_eq!(filtered["user"]["email"], "john@example.com");
		assert!(filtered["user"].get("bio").is_none());
	}

	#[test]
	fn test_filter_arrays() {
		let over_500 = "c".repeat(530);
		let data = json!({
			"items": [
				"valid item 1",
				over_500.clone(),
				"valid item 2"
			]
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// Should have one violation
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "items[1]");
		
		// Array should still have 3 items (long one becomes null)
		assert_eq!(filtered["items"].as_array().unwrap().len(), 3);
		assert_eq!(filtered["items"][0], "valid item 1");
		assert!(filtered["items"][1].is_null());
		assert_eq!(filtered["items"][2], "valid item 2");
	}

	#[test]
	fn test_filter_multiple_violations() {
		let over_500_1 = "d".repeat(510);
		let over_500_2 = "e".repeat(540);
		let data = json!({
			"field1": over_500_1.clone(),
			"valid": "good",
			"nested": {
				"field2": over_500_2.clone(),
				"also_valid": "fine"
			}
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// Should have two violations
		assert_eq!(violations.len(), 2);
		assert!(violations.iter().any(|v| v.path == "field1"));
		assert!(violations.iter().any(|v| v.path == "nested.field2"));
		
		// Filtered should only have valid fields
		assert!(filtered.get("field1").is_none());
		assert_eq!(filtered["valid"], "good");
		assert!(filtered["nested"].get("field2").is_none());
		assert_eq!(filtered["nested"]["also_valid"], "fine");
	}

	#[test]
	fn test_filter_complex_nested_structure() {
		let over_500 = "x".repeat(505);
		let data = json!({
			"payload": {
				"events": [
					{
						"event_type": "click",
						"event_properties": {
							"description": over_500.clone(),
							"page": "home"
						}
					}
				]
			}
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// Should have one violation
		assert_eq!(violations.len(), 1);
		assert_eq!(violations[0].path, "payload.events[0].event_properties.description");
		
		// Structure preserved but description removed
		assert_eq!(filtered["payload"]["events"][0]["event_type"], "click");
		assert_eq!(filtered["payload"]["events"][0]["event_properties"]["page"], "home");
		assert!(filtered["payload"]["events"][0]["event_properties"]
			.get("description")
			.is_none());
	}

	#[test]
	fn test_filter_with_exactly_500_chars() {
		let exactly_500 = "a".repeat(500);
		let data = json!({
			"field": exactly_500.clone()
		});

		let (filtered, violations) = validate_and_filter(&data);
		
		// No violations - exactly 500 is allowed
		assert!(violations.is_empty());
		assert_eq!(filtered["field"], exactly_500);
	}
}
